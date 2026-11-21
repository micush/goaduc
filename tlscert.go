package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	certValidity = 825 * 24 * time.Hour
	certRenewAt  = 30 * 24 * time.Hour
)

// localIPs returns the addresses of all local interfaces.
func localIPs() []net.IP {
	var out []net.IP
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			out = append(out, ipn.IP)
		}
	}
	return out
}

// generateSelfSigned writes a new ECDSA P-256 self-signed certificate and key.
func generateSelfSigned(certPath, keyPath string, extraHosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"goaduc self-signed"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	seen := map[string]bool{}
	addName := func(n string) {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	addName(host)
	addName("localhost")
	for _, h := range extraHosts {
		addName(h)
	}
	for _, ip := range append([]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, localIPs()...) {
		if ip != nil && !ip.IsLinkLocalUnicast() {
			addName(ip.String())
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return err
	}
	if err := writeAtomic(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return err
	}
	return writeAtomic(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// certNeedsRenewal reports whether the cert at path is unreadable or expires soon.
func certNeedsRenewal(certPath string) bool {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return true
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return true
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return true
	}
	return time.Until(c.NotAfter) < certRenewAt
}

// ensureCert makes sure a usable cert/key pair exists. When auto is true
// (paths are the defaults) a missing or soon-to-expire cert is regenerated;
// explicit user-supplied paths must already exist.
func ensureCert(certPath, keyPath string, auto bool) error {
	_, e1 := os.Stat(certPath)
	_, e2 := os.Stat(keyPath)
	if !auto {
		if e1 != nil || e2 != nil {
			return fmt.Errorf("TLS certificate/key not found: %s, %s", certPath, keyPath)
		}
		return nil
	}
	if e1 != nil || e2 != nil || certNeedsRenewal(certPath) {
		if e1 == nil && e2 == nil {
			log.Printf("certificate expiring or invalid; regenerating")
		}
		return generateSelfSigned(certPath, keyPath, nil)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		// mismatched or corrupt pair we manage: replace it
		return generateSelfSigned(certPath, keyPath, nil)
	}
	return nil
}

// certFingerprint returns the SHA-256 fingerprint of the first cert in a PEM file.
func certFingerprint(certPath string) (string, error) {
	b, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return "", errors.New("no PEM certificate found")
	}
	sum := sha256.Sum256(blk.Bytes)
	parts := make([]string, len(sum))
	for i, v := range sum {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":"), nil
}

// defaultDataDir picks the state directory.
func defaultDataDir() string {
	if os.Geteuid() == 0 {
		return "/var/lib/goaduc"
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "goaduc")
	}
	return ".goaduc"
}
