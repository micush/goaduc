package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCertPEM(t *testing.T, cn string, names []string, notAfter time.Time) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter, DNSNames: names,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
}

func TestWebCertSettings(t *testing.T) {
	old := webCert
	defer func() { webCert = old }()
	webCert = &webCertMgr{}
	dir := filepath.Join(t.TempDir(), "tls")
	if err := webCert.initAuto(dir); err != nil {
		t.Fatal(err)
	}
	c, d := setup(t)
	st := c.ok("GET", "/api/settings/cert", nil)
	if st["managed"] != true || st["custom"] != false || st["selfSigned"] != true {
		t.Fatalf("%v", st)
	}
	good, goodKey := testCertPEM(t, "goaduc.example.com", []string{"goaduc.example.com", "dc1"}, time.Now().Add(90*24*time.Hour))
	// not a Domain Admin yet
	c.fail("POST", "/api/settings/cert/save", map[string]any{"cert": good, "key": goodKey}, "only Domain Admins")
	da := "CN=Domain Admins,CN=Users," + tBase
	d.mu.Lock()
	d.put("CN=admin,CN=Users,"+tBase, "objectClass", "top", "objectClass", "person", "objectClass", "user", "sAMAccountName", "admin",
		"userPrincipalName", "admin@samdom.example.com", "memberOf", da)
	d.mu.Unlock()

	_, otherKey := testCertPEM(t, "other", []string{"other.example.com"}, time.Now().Add(time.Hour*24))
	c.fail("POST", "/api/settings/cert/save", map[string]any{"cert": good, "key": otherKey}, "do not match")
	c.fail("POST", "/api/settings/cert/save", map[string]any{"cert": good, "key": ""}, "both required")
	enc := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("x")}))
	c.fail("POST", "/api/settings/cert/save", map[string]any{"cert": good, "key": enc}, "passphrase")
	exp, expKey := testCertPEM(t, "old", []string{"old.example.com"}, time.Now().Add(-time.Hour))
	c.fail("POST", "/api/settings/cert/save", map[string]any{"cert": exp, "key": expKey}, "expired")
	nosan, nosanKey := testCertPEM(t, "nosan", nil, time.Now().Add(time.Hour*24))
	c.fail("POST", "/api/settings/cert/save", map[string]any{"cert": nosan, "key": nosanKey}, "alternative names")
	if webCert.custom {
		t.Fatal("a refused upload changed the certificate")
	}

	st = c.ok("POST", "/api/settings/cert/save", map[string]any{"cert": good, "key": goodKey})
	if st["custom"] != true || st["selfSigned"] != true || !strings.Contains(st["subject"].(string), "goaduc.example.com") {
		t.Fatalf("%v", st)
	}
	got, _ := webCert.getCertificate(nil)
	if leaf, _ := x509.ParseCertificate(got.Certificate[0]); leaf.Subject.CommonName != "goaduc.example.com" {
		t.Fatal("the served certificate was not swapped")
	}
	cc, ck := webCert.customPaths()
	if st, err := os.Stat(ck); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	if _, err := tls.LoadX509KeyPair(cc, ck); err != nil {
		t.Fatal(err)
	}
	// a restart picks the uploaded pair again
	again := &webCertMgr{}
	if err := again.initAuto(dir); err != nil || !again.custom {
		t.Fatalf("restart: %v custom=%v", err, again.custom)
	}
	// the audit trail must not carry the key
	for _, e := range auditRing {
		if strings.Contains(e.Detail, "PRIVATE KEY") {
			t.Fatalf("private key in the audit log: %s", e.Detail)
		}
	}

	st = c.ok("POST", "/api/settings/cert/reset", map[string]any{})
	if st["custom"] != false {
		t.Fatalf("%v", st)
	}
	if _, err := os.Stat(cc); err == nil {
		t.Fatal("uploaded certificate not removed")
	}

	// -tls-cert/-tls-key mode and plain HTTP are read-only
	selfCert := webCert.cur
	webCert = &webCertMgr{managed: false}
	webCert.set(selfCert, false)
	c.fail("POST", "/api/settings/cert/save", map[string]any{"cert": good, "key": goodKey}, "-tls-cert")
	if st := c.ok("GET", "/api/settings/cert", nil); st["managed"] != false || st["why"] == nil {
		t.Fatalf("%v", st)
	}
	webCert = &webCertMgr{plain: true}
	if st := c.ok("GET", "/api/settings/cert", nil); st["plain"] != true {
		t.Fatalf("%v", st)
	}
}

// A real handshake sees the swapped certificate without the listener restarting.
func TestWebCertLiveSwap(t *testing.T) {
	m := &webCertMgr{}
	if err := m.initAuto(filepath.Join(t.TempDir(), "tls")); err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: m.getCertificate})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	cn := func() string {
		c, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		return c.ConnectionState().PeerCertificates[0].Subject.CommonName
	}
	before := cn()
	certPEM, keyPEM := testCertPEM(t, "swapped.example.com", []string{"swapped.example.com"}, time.Now().Add(24*time.Hour))
	c, err := parseUploadedCert(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	m.set(c, true)
	if after := cn(); after != "swapped.example.com" || after == before {
		t.Fatalf("handshake served %q (before %q)", after, before)
	}
}
