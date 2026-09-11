package agentapi

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestTLSCertificatePersistenceAndFailure(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	first, err := LoadOrGenerateCert(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrGenerateCert(certPath, keyPath)
	if err != nil || !bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("certificate changed on restart", err)
	}
	if err := os.WriteFile(keyPath, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateCert(certPath, keyPath); err == nil {
		t.Fatal("corrupt existing key silently replaced")
	}
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateCert(filepath.Join(blocker, "cert.pem"), filepath.Join(blocker, "key.pem")); err == nil {
		t.Fatal("unpersisted certificate accepted")
	}
}
