package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/NaNA1337/super-proxy/internal/config"
	"github.com/NaNA1337/super-proxy/internal/database"
)

func runDatabaseCommand(args []string) error {
	if len(args) == 0 || args[0] != "clean" {
		return errors.New("usage: super-proxy database clean -yes [-config /etc/super-proxy/config.yaml]")
	}

	flags := flag.NewFlagSet("database clean", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	configPath := flags.String("config", "/etc/super-proxy/config.yaml", "Core YAML configuration path")
	confirmed := flags.Bool("yes", false, "confirm database rotation and fresh initialization")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument: %s", strings.Join(flags.Args(), " "))
	}
	if !*confirmed {
		return errors.New("refusing to clean without -yes; the existing database will be retained as an automatic backup")
	}
	if os.Geteuid() != 0 {
		return errors.New("database clean must run as root")
	}
	if running, err := daemonPIDRunning("/var/run/super-proxy.pid"); err != nil {
		return err
	} else if running {
		return errors.New("super-proxy is still running; stop the service before cleaning the database")
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load config %q: %w", *configPath, err)
	}
	dbPath := cfg.Database.Path
	if !filepath.IsAbs(dbPath) {
		return fmt.Errorf("database.path in %q must be absolute before cleaning: %q", *configPath, dbPath)
	}

	backupPath, err := database.CleanDatabase(dbPath)
	if err != nil {
		return err
	}
	fmt.Printf("Database cleaned successfully.\nFresh database: %s\nBackup: %s\nConfiguration and client credentials were not changed.\n", dbPath, backupPath)
	return nil
}

func daemonPIDRunning(pidPath string) (bool, error) {
	raw, err := os.ReadFile(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read daemon PID file: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return false, nil
	}
	err = syscall.Kill(pid, 0)
	if err == nil || errors.Is(err, syscall.EPERM) {
		return true, nil
	}
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	return false, fmt.Errorf("check daemon process %d: %w", pid, err)
}
