package httpapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDashboardRoutesRejectAnonymous(t *testing.T) {
	app := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{Origins: []string{"https://rmm.example.test"}})
	for _, path := range []string{"/core/dashinfo/", "/ws/dashinfo/"} {
		response, err := app.Test(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 401 {
			t.Fatalf("%s: got %d", path, response.StatusCode)
		}
	}
}

func TestDashboardCertificateDays(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "api.example.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(49 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TLS_CERT_FILE", path)
	if got := dashboardCertDays(now); got == nil || *got != 2 {
		t.Fatalf("valid certificate days: %v", got)
	}
	if got := dashboardCertDays(now.Add(50 * time.Hour)); got == nil || *got != -1 {
		t.Fatalf("expired certificate must round down: %v", got)
	}
	t.Setenv("TLS_CERT_FILE", filepath.Join(t.TempDir(), "missing"))
	if dashboardCertDays(now) != nil {
		t.Fatal("unknown certificate expiry must not be fabricated")
	}
}
