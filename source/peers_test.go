package main

import (
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePeer stands in for the goaduc on another DC: it records what it is asked and answers like the real endpoints.
type fakePeer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	logins   []map[string]string
	purges   []map[string]any
	purgeErr string
	leaf     []byte
}

func newFakePeer(t *testing.T) *fakePeer {
	fp := &fakePeer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		fp.mu.Lock()
		fp.logins = append(fp.logins, in)
		fp.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "aduc", Value: "tok"})
		w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/logout", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"ok":true}`)) })
	mux.HandleFunc("/api/deleted/purge", func(w http.ResponseWriter, r *http.Request) {
		if ck, err := r.Cookie("aduc"); err != nil || ck.Value != "tok" || r.Header.Get("X-Requested-With") != "aduc" {
			w.WriteHeader(401)
			return
		}
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		fp.mu.Lock()
		fp.purges = append(fp.purges, in)
		msg := fp.purgeErr
		fp.mu.Unlock()
		if msg != "" {
			w.WriteHeader(500)
			json.NewEncoder(w).Encode(map[string]string{"error": msg})
			return
		}
		w.Write([]byte(`{"deleted":3}`))
	})
	// every fake peer gets its own self-signed certificate (httptest's built-in one is shared by all servers)
	certPEM, keyPEM := testCertPEM(t, "dc2", []string{"dc2.samdom.example.com"}, time.Now().Add(24*time.Hour))
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	fp.leaf = pair.Certificate[0]
	fp.srv = httptest.NewUnstartedServer(mux)
	fp.srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	fp.srv.StartTLS()
	t.Cleanup(fp.srv.Close)
	return fp
}

func (fp *fakePeer) fingerprint() string { return certSHA256(fp.leaf) }
func (fp *fakePeer) counts() (int, int) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	return len(fp.logins), len(fp.purges)
}

func TestPurgeOnOtherDCs(t *testing.T) {
	c, d := setup(t)
	// the local fallback conditions: refused, root with a sam.db, a Domain Admin
	mockRefusePurge.Store(true)
	osam, ostool, oldb, ousable, oaddr := samDB, sambaToolRun, ldbDelLocal, samDBUsable, peerAddr
	t.Cleanup(func() {
		mockRefusePurge.Store(false)
		samDB, sambaToolRun, ldbDelLocal, samDBUsable, peerAddr = osam, ostool, oldb, ousable, oaddr
		peerMu.Lock()
		peerPins = map[string]string{}
		peerFile = ""
		peerMu.Unlock()
	})
	samDB, samDBUsable = "/scratch/sam.ldb", func() bool { return true }
	localRuns := 0
	sambaToolRun = func(args ...string) error {
		localRuns++
		d.mu.Lock()
		for k, o := range d.dir {
			if o.str("isDeleted") == "TRUE" && strings.Contains(k, ",cn=deleted objects,") {
				delete(d.dir, k)
			}
		}
		d.mu.Unlock()
		return nil
	}
	peerMu.Lock()
	peerPins, peerFile = map[string]string{}, t.TempDir()+"/peers.json"
	peerMu.Unlock()
	da := "CN=Domain Admins,CN=Users," + tBase
	d.mu.Lock()
	d.put("CN=admin,CN=Users,"+tBase, "objectClass", "top", "objectClass", "person", "objectClass", "user", "sAMAccountName", "admin",
		"userPrincipalName", "admin@samdom.example.com", "memberOf", da)
	d.put("CN=DC2,CN=Servers,CN=Default-First-Site-Name,"+tSites, "objectClass", "server", "name", "DC2", "dNSHostName", "dc2.samdom.example.com")
	d.put("CN=NTDS Settings,CN=DC2,CN=Servers,CN=Default-First-Site-Name,"+tSites, "objectClass", "nTDSDSA", "name", "NTDS Settings", "options", "0")
	d.mu.Unlock()

	peer := newFakePeer(t)
	_, port, _ := net.SplitHostPort(peer.srv.Listener.Addr().String())
	peerAddr = func(host string) string { return net.JoinHostPort("127.0.0.1", port) }
	c.ok("POST", "/api/delete", map[string]any{"dn": "CN=alice,OU=Staff," + tBase})

	// 1. the page is asked first: this DC is not offered itself, the other one shows its certificate and that it is new
	r := c.ok("POST", "/api/deleted/purge", map[string]any{"all": true})
	ps := list(r["peers"])
	if r["needsLocal"] != true || len(ps) != 1 {
		t.Fatalf("%v", r)
	}
	p0 := ps[0].(map[string]any)
	if p0["host"] != "dc2.samdom.example.com" || p0["state"] != "new" || p0["fingerprint"] != peer.fingerprint() {
		t.Fatalf("%v", p0)
	}
	if localRuns != 0 {
		t.Fatal("ran before being agreed to")
	}

	// 2. an unapproved self-signed certificate: the password is never sent
	r = c.ok("POST", "/api/deleted/purge", map[string]any{"all": true, "local": true, "peers": []map[string]string{{"host": "dc2.samdom.example.com"}}})
	pr := list(r["peers"])
	if localRuns != 1 || len(pr) != 1 || pr[0].(map[string]any)["ok"] == true || !strings.Contains(pr[0].(map[string]any)["error"].(string), "not trusted") {
		t.Fatalf("runs=%d %v", localRuns, r)
	}
	if l, p := peer.counts(); l != 0 || p != 0 {
		t.Fatalf("credentials went to an untrusted peer: %d logins, %d purges", l, p)
	}
	// a wrong fingerprint is refused the same way
	r = c.ok("POST", "/api/deleted/purge", map[string]any{"all": true, "local": true, "peers": []map[string]string{{"host": "dc2.samdom.example.com", "fingerprint": "AA:BB"}}})
	if l, _ := peer.counts(); l != 0 || list(r["peers"])[0].(map[string]any)["ok"] == true {
		t.Fatalf("wrong fingerprint accepted: %v", r)
	}
	// a host that is not a DC of this domain is never contacted
	r = c.ok("POST", "/api/deleted/purge", map[string]any{"all": true, "local": true, "peers": []map[string]string{{"host": "evil.example.com", "fingerprint": peer.fingerprint()}}})
	if e := list(r["peers"])[0].(map[string]any)["error"].(string); !strings.Contains(e, "not a domain controller") {
		t.Fatalf("%v", r)
	}

	// 3. approved: signs in as the user, purges locally there, and the certificate is remembered
	r = c.ok("POST", "/api/deleted/purge", map[string]any{"all": true, "local": true, "peers": []map[string]string{{"host": "dc2.samdom.example.com", "fingerprint": peer.fingerprint()}}})
	pr = list(r["peers"])
	if len(pr) != 1 || pr[0].(map[string]any)["ok"] != true || pr[0].(map[string]any)["deleted"] != 3.0 {
		t.Fatalf("%v", r)
	}
	if len(peer.logins) != 1 || peer.logins[0]["username"] != "admin@samdom.example.com" || peer.logins[0]["password"] != "secret" {
		t.Fatalf("%v", peer.logins)
	}
	if len(peer.purges) != 1 || peer.purges[0]["all"] != true || peer.purges[0]["local"] != true {
		t.Fatalf("%v", peer.purges)
	}
	if peerPinGet("dc2.samdom.example.com") != peer.fingerprint() {
		t.Fatal("approved certificate not remembered")
	}
	c.ok("POST", "/api/delete", map[string]any{"dn": "CN=bob,OU=Staff," + tBase})
	r = c.ok("POST", "/api/deleted/purge", map[string]any{"all": true})
	if st := list(r["peers"])[0].(map[string]any)["state"]; st != "pinned" {
		t.Fatalf("state %v", st)
	}

	// 4. a different certificate later is "changed" and not used unless approved again
	other := newFakePeer(t)
	_, port2, _ := net.SplitHostPort(other.srv.Listener.Addr().String())
	peerAddr = func(host string) string { return net.JoinHostPort("127.0.0.1", port2) }
	c.ok("POST", "/api/delete", map[string]any{"dn": "CN=carol,OU=Staff," + tBase})
	r = c.ok("POST", "/api/deleted/purge", map[string]any{"all": true})
	if st := list(r["peers"])[0].(map[string]any)["state"]; st != "changed" {
		t.Fatalf("state %v", st)
	}
	r = c.ok("POST", "/api/deleted/purge", map[string]any{"all": true, "local": true, "peers": []map[string]string{{"host": "dc2.samdom.example.com", "fingerprint": peer.fingerprint()}}})
	if l, _ := other.counts(); l != 0 {
		t.Fatal("credentials went to a peer with a changed certificate")
	}

	// 5. the peer fails: that is reported, and what this DC did stands
	peer.mu.Lock()
	peer.purgeErr = "permission denied"
	peer.mu.Unlock()
	peerAddr = func(host string) string { return net.JoinHostPort("127.0.0.1", port) }
	c.ok("POST", "/api/delete", map[string]any{"dn": "CN=dave,OU=Staff," + tBase})
	before := localRuns
	r = c.ok("POST", "/api/deleted/purge", map[string]any{"all": true, "local": true, "peers": []map[string]string{{"host": "dc2.samdom.example.com", "fingerprint": peer.fingerprint()}}})
	if e := list(r["peers"])[0].(map[string]any); e["ok"] == true || !strings.Contains(e["error"].(string), "permission denied") || localRuns != before+1 {
		t.Fatalf("%v runs %d", r, localRuns)
	}
	// unreachable peer
	peerAddr = func(host string) string { return "127.0.0.1:1" }
	c.ok("POST", "/api/delete", map[string]any{"dn": "CN=erin,OU=Staff," + tBase})
	r = c.ok("POST", "/api/deleted/purge", map[string]any{"all": true})
	if st := list(r["peers"])[0].(map[string]any)["state"]; st != "unreachable" {
		t.Fatalf("state %v", st)
	}
}
