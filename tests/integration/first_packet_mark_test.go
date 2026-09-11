package integration

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/NaNA1337/super-proxy/internal/routing"
)

// A new flow has connmark=0. Restoring it unconditionally erased Xray's socket
// mark, so the first packet could leave via the underlay instead of its VPN.
func TestFirstPacketPreservesSocketMark(t *testing.T) {
	if os.Getenv("SP_MARK_TEST_CHILD") == "1" {
		if err := routing.SetupSlotRouting(0, "dummy0"); err != nil {
			t.Fatal(err)
		}
		dialer := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) { sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, 100) })
			if err != nil {
				return err
			}
			return sockErr
		}}
		conn, err := dialer.DialContext(context.Background(), "udp4", "198.51.100.99:443")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("first-packet-mark-test")); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command("conntrack", "-L", "-p", "udp", "-o", "extended").CombinedOutput()
		if err != nil || !strings.Contains(string(out), "mark=100") {
			t.Fatalf("first packet lost SO_MARK: %s (%v)", out, err)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root and network namespaces")
	}
	if _, err := exec.LookPath("conntrack"); err != nil {
		t.Skip("conntrack unavailable")
	}
	ns := fmt.Sprintf("sp_mark_%d", time.Now().UnixNano()%1000000)
	if out, err := exec.Command("ip", "netns", "add", ns).CombinedOutput(); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	defer exec.Command("ip", "netns", "del", ns).Run()
	for _, args := range [][]string{{"link", "set", "lo", "up"}, {"link", "add", "dummy0", "type", "dummy"}, {"link", "set", "dummy0", "up"}, {"addr", "add", "192.0.2.1/32", "dev", "dummy0"}} {
		if out, err := runInNetNS(ns, "ip", args...); err != nil {
			t.Fatalf("%s: %v", out, err)
		}
	}
	cmd := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestFirstPacketPreservesSocketMark$", "-test.v")
	cmd.Env = append(os.Environ(), "SP_MARK_TEST_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
}
