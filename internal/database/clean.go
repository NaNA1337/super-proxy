package database

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

// CleanDatabase replaces an existing Core cache database with a fresh current-schema
// database. The original database is retained beside it as a timestamped backup.
func CleanDatabase(dbPath string) (string, error) {
	return cleanDatabaseAt(dbPath, time.Now().UTC())
}

func cleanDatabaseAt(dbPath string, now time.Time) (string, error) {
	if !filepath.IsAbs(dbPath) {
		return "", fmt.Errorf("database path must be absolute: %q", dbPath)
	}
	info, err := os.Stat(dbPath)
	if err != nil {
		return "", fmt.Errorf("database is not accessible: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("database path is not a regular file: %q", dbPath)
	}

	// Refuse to rotate a corrupt database silently. A readable backup remains useful
	// for recovery and audit, so validate and checkpoint WAL before moving any files.
	oldDB, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return "", fmt.Errorf("open existing database: %w", err)
	}
	sqlDB, err := oldDB.DB()
	if err != nil {
		return "", fmt.Errorf("access existing database connection: %w", err)
	}
	closeOld := func() { _ = sqlDB.Close() }

	var integrity string
	if err := sqlDB.QueryRow("PRAGMA integrity_check;").Scan(&integrity); err != nil {
		closeOld()
		return "", fmt.Errorf("check database integrity: %w", err)
	}
	if integrity != "ok" {
		closeOld()
		return "", fmt.Errorf("database integrity check failed: %s", integrity)
	}
	if _, err := sqlDB.Exec("PRAGMA wal_checkpoint(TRUNCATE);"); err != nil {
		closeOld()
		return "", fmt.Errorf("checkpoint database WAL (is super-proxy still running?): %w", err)
	}
	if _, err := sqlDB.Exec("PRAGMA journal_mode=DELETE;"); err != nil {
		closeOld()
		return "", fmt.Errorf("close database WAL (is super-proxy still running?): %w", err)
	}
	closeOld()

	backupPath := fmt.Sprintf("%s.backup-%s", dbPath, now.Format("20060102T150405.000000000Z"))
	if _, err := os.Stat(backupPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return "", fmt.Errorf("backup path already exists: %q", backupPath)
		}
		return "", fmt.Errorf("check backup path: %w", err)
	}

	moved := make([]string, 0, 3)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		source := dbPath + suffix
		target := backupPath + suffix
		if err := os.Rename(source, target); err != nil {
			if errors.Is(err, os.ErrNotExist) && suffix != "" {
				continue
			}
			for i := len(moved) - 1; i >= 0; i-- {
				_ = os.Rename(backupPath+moved[i], dbPath+moved[i])
			}
			return "", fmt.Errorf("move database%s to backup: %w", suffix, err)
		}
		moved = append(moved, suffix)
	}
	_ = os.Chmod(backupPath, 0600)

	if err := InitDatabase(dbPath); err != nil {
		if DB != nil {
			if freshSQL, dbErr := DB.DB(); dbErr == nil {
				_ = freshSQL.Close()
			}
			DB = nil
		}
		for _, suffix := range []string{"", "-wal", "-shm"} {
			_ = os.Remove(dbPath + suffix)
		}
		for i := len(moved) - 1; i >= 0; i-- {
			_ = os.Rename(backupPath+moved[i], dbPath+moved[i])
		}
		return "", fmt.Errorf("create fresh database (original restored): %w", err)
	}
	if DB != nil {
		freshSQL, dbErr := DB.DB()
		if dbErr != nil {
			return "", fmt.Errorf("access fresh database connection: %w", dbErr)
		}
		if err := freshSQL.Close(); err != nil && !errors.Is(err, sql.ErrConnDone) {
			return "", fmt.Errorf("close fresh database: %w", err)
		}
		DB = nil
	}
	if err := os.Chmod(dbPath, 0600); err != nil {
		return "", fmt.Errorf("secure fresh database permissions: %w", err)
	}
	return backupPath, nil
}
