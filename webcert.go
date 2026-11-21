package main

// Settings → Certificate: the web UI's own TLS certificate. In the default (auto) mode goaduc keeps a
// self-signed pair (server.crt/server.key) and an optional uploaded pair (custom.crt/custom.key) in
// <data dir>/tls; the uploaded pair wins when it loads. The served certificate is swapped live
// (tls.Config.GetCertificate), so a new one needs no restart. With -tls-cert/-tls-key the files are
// the operator's own and the page is read-only.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type webCertMgr struct {
	mu      sync.RWMutex
	cur     *tls.Certificate
	dir     string // <data dir>/tls (auto mode only)
	managed bool   // auto mode: goaduc owns the files and the page may change them
	plain   bool   // served over plain HTTP: there is no certificate
	custom  bool   // the uploaded pair is the one in use
	path    string // file shown as the source in non-managed mode
}

var webCert = &webCertMgr{}

func (m *webCertMgr) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cur, nil
}

func (m *webCertMgr) set(c *tls.Certificate, custom bool) {
	m.mu.Lock()
	m.cur, m.custom = c, custom
	m.mu.Unlock()
}

func (m *webCertMgr) customPaths() (string, string) {
	return filepath.Join(m.dir, "custom.crt"), filepath.Join(m.dir, "custom.key")
}

// initAuto picks the uploaded pair if it loads, otherwise the (auto-renewed) self-signed one.
func (m *webCertMgr) initAuto(dir string) error {
	m.dir, m.managed = dir, true
	cc, ck := m.customPaths()
	if _, err := os.Stat(cc); err == nil {
		if c, err := tls.LoadX509KeyPair(cc, ck); err == nil {
			m.set(&c, true)
			return nil
		} else {
			log.Printf("uploaded web certificate unusable (%v); using the self-signed one", err)
		}
	}
	sc, sk := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	if err := ensureCert(sc, sk, true); err != nil {
		return err
	}
	c, err := tls.LoadX509KeyPair(sc, sk)
	if err != nil {
		return err
	}
	m.set(&c, false)
	return nil
}

func (m *webCertMgr) initFiles(cert, key string) error {
	m.managed, m.path = false, cert
	c, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return err
	}
	m.set(&c, false)
	return nil
}

func certInfo(c *tls.Certificate) (map[string]any, error) {
	if c == nil || len(c.Certificate) == 0 {
		return nil, errors.New("no certificate")
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, err
	}
	names := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	sort.Strings(names)
	sum := sha256.Sum256(leaf.Raw)
	parts := make([]string, len(sum))
	for i, v := range sum {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return map[string]any{
		"subject": leaf.Subject.String(), "issuer": leaf.Issuer.String(), "names": names,
		"notBefore": leaf.NotBefore.UTC().Format(time.RFC3339), "notAfter": leaf.NotAfter.UTC().Format(time.RFC3339),
		"fingerprint": strings.Join(parts, ":"), "selfSigned": leaf.Subject.String() == leaf.Issuer.String(),
		"chain": len(c.Certificate),
	}, nil
}

func apiWebCert(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	m := webCert
	m.mu.RLock()
	cur, custom, managed, plain := m.cur, m.custom, m.managed, m.plain
	m.mu.RUnlock()
	out := map[string]any{"managed": managed, "custom": custom, "plain": plain}
	if plain {
		out["why"] = "the web UI is served over plain HTTP (-http), so there is no certificate"
		return out, nil
	}
	if !managed {
		out["why"] = "the certificate is set with -tls-cert/-tls-key; replace those files and restart goaduc"
	}
	info, err := certInfo(cur)
	if err != nil {
		return nil, err
	}
	for k, v := range info {
		out[k] = v
	}
	return out, nil
}

// parseUploadedCert checks a PEM certificate (or chain) and key: they must match, the key must not be
// passphrase-protected, and the leaf must be valid now.
func parseUploadedCert(certPEM, keyPEM string) (*tls.Certificate, error) {
	if strings.TrimSpace(certPEM) == "" || strings.TrimSpace(keyPEM) == "" {
		return nil, errors.New("certificate and private key are both required")
	}
	for rest := []byte(keyPEM); ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if strings.Contains(b.Type, "ENCRYPTED") || b.Headers["Proc-Type"] != "" {
			return nil, errors.New("the private key is passphrase-protected; remove the passphrase first (openssl pkey -in key.pem -out plain.pem)")
		}
	}
	c, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("certificate and key do not match or cannot be read: %v", err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, err
	}
	if now := time.Now(); now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate expired on %s", leaf.NotAfter.UTC().Format("2006-01-02"))
	} else if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("the certificate is not valid until %s", leaf.NotBefore.UTC().Format("2006-01-02"))
	}
	if len(leaf.DNSNames) == 0 && len(leaf.IPAddresses) == 0 {
		return nil, errors.New("the certificate has no subject alternative names (DNS or IP); browsers will reject it")
	}
	return &c, nil
}

func certChangeAllowed(s *Session) error {
	m := webCert
	if m.plain {
		return errors.New("the web UI is served over plain HTTP, so there is no certificate to change")
	}
	if !m.managed {
		return errors.New("the certificate is set with -tls-cert/-tls-key; replace those files and restart goaduc")
	}
	var ok bool
	if err := s.With(func(c *Conn) (e error) { ok, e = isDomainAdmin(c, s); return e }); err != nil {
		return err
	}
	if !ok {
		return errors.New("only Domain Admins or Enterprise Admins can change the web certificate")
	}
	return nil
}

func apiWebCertSave(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	if r.Method != http.MethodPost {
		return nil, errors.New("POST only")
	}
	if err := certChangeAllowed(s); err != nil {
		return nil, err
	}
	var in struct{ Cert, Key string }
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	c, err := parseUploadedCert(in.Cert, in.Key)
	if err != nil {
		return nil, err
	}
	m := webCert
	cc, ck := m.customPaths()
	if err := os.MkdirAll(m.dir, 0o700); err != nil {
		return nil, err
	}
	// key first: a crash between the two leaves a pair that fails to load, and startup then falls back to self-signed
	if err := writeAtomic(ck, []byte(in.Key), 0o600); err != nil {
		return nil, err
	}
	if err := writeAtomic(cc, []byte(in.Cert), 0o644); err != nil {
		return nil, err
	}
	m.set(c, true)
	if fp, err := certFingerprint(cc); err == nil {
		log.Printf("web certificate replaced by %s  SHA-256 %s", s.user, fp)
	}
	return apiWebCert(w, r, s)
}

func apiWebCertReset(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	if r.Method != http.MethodPost {
		return nil, errors.New("POST only")
	}
	if err := certChangeAllowed(s); err != nil {
		return nil, err
	}
	m := webCert
	sc, sk := filepath.Join(m.dir, "server.crt"), filepath.Join(m.dir, "server.key")
	if err := ensureCert(sc, sk, true); err != nil {
		return nil, err
	}
	c, err := tls.LoadX509KeyPair(sc, sk)
	if err != nil {
		return nil, err
	}
	cc, ck := m.customPaths()
	os.Remove(cc)
	os.Remove(ck)
	m.set(&c, false)
	log.Printf("web certificate reset to self-signed by %s", s.user)
	return apiWebCert(w, r, s)
}

func registerWebCert(mux *http.ServeMux) {
	mux.HandleFunc("/api/settings/cert", auth(apiWebCert))
	mux.HandleFunc("/api/settings/cert/save", auth(apiWebCertSave))
	mux.HandleFunc("/api/settings/cert/reset", auth(apiWebCertReset))
}
