package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestDNSRecordVectors(t *testing.T) {
	// A 10.0.0.1, ttl 3600, serial 1 (layout from MS-DNSP 2.2.2.2.2)
	want := []byte{4, 0, 1, 0, 5, 240, 0, 0, 1, 0, 0, 0, 0, 0, 0x0e, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1}
	got, err := encodeDNSRecord("A", map[string]any{"address": "10.0.0.1"}, 3600, 1)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%v %v", got, err)
	}
	// DNS_COUNT_NAME for "ns.example.com": length counts the labels plus the terminator
	n, _ := encodeCountName("ns.example.com.")
	if !bytes.Equal(n, append([]byte{16, 3, 2}, append([]byte("ns"), append([]byte{7}, append([]byte("example"), append([]byte{3}, append([]byte("com"), 0)...)...)...)...)...)) {
		t.Fatalf("%v", n)
	}
}

func TestDNSRoundTrip(t *testing.T) {
	cases := []struct {
		typ string
		f   map[string]any
		txt string
	}{
		{"A", map[string]any{"address": "192.168.1.5"}, "192.168.1.5"},
		{"AAAA", map[string]any{"address": "fd00::1"}, "fd00::1"},
		{"CNAME", map[string]any{"target": "web.example.com"}, "web.example.com."},
		{"NS", map[string]any{"target": "dc1.example.com."}, "dc1.example.com."},
		{"PTR", map[string]any{"target": "host.example.com"}, "host.example.com."},
		{"MX", map[string]any{"preference": 10.0, "target": "mail.example.com"}, "[10] mail.example.com."},
		{"SRV", map[string]any{"priority": "0", "weight": "100", "port": 389.0, "target": "dc1.example.com"}, "[0][100][389] dc1.example.com."},
		{"TXT", map[string]any{"text": "v=spf1 -all"}, "v=spf1 -all"},
		{"SOA", map[string]any{"serial": 5.0, "refresh": 900.0, "retry": 600.0, "expire": 86400.0, "minimum": 3600.0, "primary": "dc1.example.com", "admin": "hostmaster.example.com"}, "[5] dc1.example.com. hostmaster.example.com."},
	}
	for _, c := range cases {
		b, err := encodeDNSRecord(c.typ, c.f, 600, 7)
		if err != nil {
			t.Fatalf("%s: %v", c.typ, err)
		}
		r, _, err := decodeDNSRecord(b)
		if err != nil || r.Type != c.typ || r.Text != c.txt || r.TTL != 600 || r.Serial != 7 || r.Dynamic {
			t.Fatalf("%s: %+v %v", c.typ, r, err)
		}
		if raw, _ := base64.StdEncoding.DecodeString(r.Raw); !bytes.Equal(raw, b) {
			t.Fatalf("%s raw mismatch", c.typ)
		}
	}
	long := bytes.Repeat([]byte("x"), 600)
	b, _ := encodeDNSRecord("TXT", map[string]any{"text": string(long)}, 60, 1)
	if r, _, err := decodeDNSRecord(b); err != nil || r.Text != string(long) {
		t.Fatal("long TXT")
	}
}

func TestDNSValidation(t *testing.T) {
	for _, c := range []struct {
		typ string
		f   map[string]any
	}{
		{"A", map[string]any{"address": "::1"}}, {"A", map[string]any{"address": "999.1.1.1"}}, {"AAAA", map[string]any{"address": "1.2.3.4"}},
		{"CNAME", map[string]any{"target": ""}}, {"MX", map[string]any{"preference": "x", "target": "a.b"}},
		{"SRV", map[string]any{"priority": 1.0, "weight": 1.0, "port": 70000.0, "target": "a.b"}}, {"BOGUS", nil},
	} {
		if _, err := encodeDNSRecord(c.typ, c.f, 1, 1); err == nil {
			t.Errorf("%s %v should fail", c.typ, c.f)
		}
	}
	if _, err := encodeCountName("a..b"); err == nil {
		t.Error("empty label")
	}
	// tombstone and unknown types
	tomb := make([]byte, 32)
	tomb[2] = 0
	tomb[0] = 8
	if r, _, err := decodeDNSRecord(tomb); r != nil || err != nil {
		t.Error("tombstone should be skipped")
	}
	unk := append(make([]byte, 24), 1, 2)
	unk[0], unk[2] = 2, 99
	if r, _, _ := decodeDNSRecord(unk); r == nil || r.Editable || r.Type != "TYPE99" {
		t.Error("unknown type")
	}
}

func TestPolicyConversions(t *testing.T) {
	if intervalToUnits("-36288000000000", day100ns) != 42 || intervalToUnits("-9223372036854775808", day100ns) != 0 || intervalToUnits("0", day100ns) != 0 {
		t.Error("intervalToUnits")
	}
	if unitsToInterval(42, day100ns) != "-36288000000000" || unitsToInterval(30, min100ns) != "-18000000000" || unitsToInterval(0, min100ns) != "0" {
		t.Error("unitsToInterval")
	}
	if validatePolicy(policyDTO{MinLength: 7, History: 24, MaxAgeDays: 42, MinAgeDays: 1, Threshold: 5, DurationMin: 30, WindowMin: 30}) != nil {
		t.Error("valid policy rejected")
	}
	for _, p := range []policyDTO{{MinLength: 300}, {MaxAgeDays: 10, MinAgeDays: 10}, {Threshold: 3}, {Threshold: 3, WindowMin: 60, DurationMin: 30}} {
		if validatePolicy(p) == nil {
			t.Errorf("%+v should fail", p)
		}
	}
}

func TestAuditRedaction(t *testing.T) {
	audit("u", "/api/password", []byte(`{"dn":"CN=x","password":"secret","nested":{"pw2":"s","pwdLastSet":"0"},"newPassword":"z"}`), nil)
	auditMu.Lock()
	e := auditRing[len(auditRing)-1]
	auditMu.Unlock()
	var m map[string]any
	json.Unmarshal([]byte(e.Detail), &m)
	if m["password"] != "***" || m["newPassword"] != "***" || m["nested"].(map[string]any)["pw2"] != "***" || m["nested"].(map[string]any)["pwdLastSet"] != "0" || m["dn"] != "CN=x" {
		t.Fatalf("%s", e.Detail)
	}
}

func TestFilters(t *testing.T) {
	for _, f := range []string{"(&" + fUser + uacBit(2) + ")", "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=CN\\3dx))",
		"(&" + fUser + "(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<=133000000000000000)))", "(isDeleted=TRUE)"} {
		if _, err := ParseFilter(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestSelfSignedCertServes(t *testing.T) {
	dir := t.TempDir()
	c, k := dir+"/tls/server.crt", dir+"/tls/server.key"
	if err := ensureCert(c, k, true); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(k); st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %v", st.Mode())
	}
	if certNeedsRenewal(c) {
		t.Fatal("fresh cert should not need renewal")
	}
	if _, err := certFingerprint(c); err != nil {
		t.Fatal(err)
	}
	if err := ensureCert(dir+"/x.crt", dir+"/x.key", false); err == nil {
		t.Fatal("explicit missing cert must error")
	}
	pair, err := tls.LoadX509KeyPair(c, k)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(securityHeaders(buildMux()))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	defer srv.Close()
	pem, _ := os.ReadFile(c)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	// httptest listens on 127.0.0.1, which is in the SANs
	u := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	resp, err := cl.Get(u + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Fatal("HSTS is per host, not per port: must not be sent")
	}
}

func TestVersionIsPlainInteger(t *testing.T) {
	v := version()
	if v == "" || strings.Trim(v, "0123456789") != "" || strings.HasPrefix(v, "0") {
		t.Fatalf("VERSION must be a plain positive integer, got %q", v)
	}
}

func TestContainerClasses(t *testing.T) {
	for _, c := range []struct {
		oc   []string
		want bool
	}{
		{[]string{"top", "organizationalUnit"}, true}, {[]string{"top", "container"}, true},
		{[]string{"top", "domain", "domainDNS"}, true}, {[]string{"top", "person", "organizationalPerson", "user"}, false},
		{[]string{"top", "group"}, false}, {[]string{"top", "dnsNode"}, false}, {[]string{"top", "msDS-OptionalFeature"}, false},
		{[]string{"top", "container", "nTDSService"}, true}, {nil, false},
	} {
		if got := isContainerClass(c.oc); got != c.want {
			t.Errorf("%v: got %v want %v", c.oc, got, c.want)
		}
	}
}
