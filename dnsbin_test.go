package main

import "testing"

func TestDNSRecycleBin(t *testing.T) {
	dir := t.TempDir()
	initDNSBin(dir)
	t.Cleanup(func() { dnsBinMu.Lock(); dnsBin, dnsBinFile = nil, ""; dnsBinMu.Unlock() })
	c, d := setup(t)
	z := list(c.ok("GET", "/api/dns/zones", nil)["zones"])
	zone := z[0].(map[string]any)["dn"].(string)
	recs := func() map[string][]map[string]any {
		out := map[string][]map[string]any{}
		for _, n := range list(c.ok("GET", "/api/dns/records?zone="+zone, nil)["nodes"]) {
			nm := n.(map[string]any)
			for _, r := range list(nm["records"]) {
				out[nm["name"].(string)] = append(out[nm["name"].(string)], r.(map[string]any))
			}
		}
		return out
	}
	save := func(name, typ string, f map[string]any) {
		c.ok("POST", "/api/dns/save", map[string]any{"zone": zone, "name": name, "type": typ, "ttl": 600, "fields": f})
	}
	save("web1", "A", map[string]any{"address": "10.0.0.50"})
	save("mail", "MX", map[string]any{"preference": 10, "target": "mx.samdom.example.com"})
	save("_sip._tcp", "SRV", map[string]any{"priority": 1, "weight": 5, "port": 5060, "target": "sip.samdom.example.com"})
	save("note", "TXT", map[string]any{"text": "hello world"})
	save("alias", "CNAME", map[string]any{"target": "web1.samdom.example.com"})
	before := recs()
	del := func(name string) {
		r := recs()[name]
		if len(r) != 1 {
			t.Fatalf("%s: %v", name, r)
		}
		c.ok("POST", "/api/dns/delete", map[string]any{"zone": zone, "name": name, "old": r[0]["raw"]})
	}
	bin := func() []any { return list(c.ok("GET", "/api/deleted", nil)["dns"]) }
	for _, n := range []string{"web1", "mail", "_sip._tcp", "note", "alias"} {
		del(n)
	}
	b := bin()
	if len(b) != 5 {
		t.Fatalf("bin has %d entries: %v", len(b), b)
	}
	first := b[0].(map[string]any) // newest first
	if first["name"] != "alias" || first["type"] != "CNAME" || first["zoneName"] != "samdom.example.com" || first["restorable"] != true || first["by"] != "admin@samdom.example.com" {
		t.Fatalf("%v", first)
	}
	if len(recs()["web1"]) != 0 {
		t.Fatal("record still in DNS")
	}
	// a restart: the list comes back from the data directory
	initDNSBin(dir)
	if len(bin()) != 5 {
		t.Fatal("not persisted")
	}
	// restore every one and compare with what was there
	idOf := func(name string) string {
		for _, e := range bin() {
			if m := e.(map[string]any); m["name"] == name {
				return m["id"].(string)
			}
		}
		t.Fatalf("%s not in the bin", name)
		return ""
	}
	for _, n := range []string{"web1", "mail", "_sip._tcp", "note"} {
		c.ok("POST", "/api/deleted/dns/restore", map[string]any{"id": idOf(n)})
		got, want := recs()[n], before[n]
		if len(got) != 1 || got[0]["type"] != want[0]["type"] || got[0]["text"] != want[0]["text"] || got[0]["ttl"] != want[0]["ttl"] {
			t.Fatalf("%s: restored %v, was %v", n, got, want)
		}
	}
	if len(bin()) != 1 {
		t.Fatalf("restored entries stay in the bin: %v", bin())
	}
	// a restore the DNS rules refuse leaves the entry
	save("alias", "A", map[string]any{"address": "10.0.0.9"})
	c.fail("POST", "/api/deleted/dns/restore", map[string]any{"id": idOf("alias")}, "CNAME")
	if len(bin()) != 1 {
		t.Fatal("a refused restore dropped the entry")
	}
	c.fail("POST", "/api/deleted/dns/restore", map[string]any{"id": "nope"}, "not in the Recycle Bin")

	// removing entries is for Domain/Enterprise Admins
	del("web1")
	del("note")
	id := idOf("web1")
	c.fail("POST", "/api/deleted/purge", map[string]any{"dns": id}, "only Domain Admins")
	c.fail("POST", "/api/deleted/purge", map[string]any{"all": true}, "only Domain Admins")
	if len(bin()) != 3 {
		t.Fatal("a non-admin removed entries")
	}
	d.mu.Lock()
	d.put("CN=admin,CN=Users,"+tBase, "objectClass", "top", "objectClass", "person", "objectClass", "user", "sAMAccountName", "admin",
		"userPrincipalName", "admin@samdom.example.com", "memberOf", "CN=Domain Admins,CN=Users,"+tBase)
	d.mu.Unlock()
	if r := c.ok("POST", "/api/deleted/purge", map[string]any{"dns": id}); r["deleted"] != 1.0 {
		t.Fatal(r)
	}
	if len(bin()) != 2 {
		t.Fatalf("%v", bin())
	}
	c.fail("POST", "/api/deleted/purge", map[string]any{"dns": id}, "not in the Recycle Bin")
	// Empty Recycle Bin takes the DNS entries too (the AD part has the one deleted user)
	if r := c.ok("POST", "/api/deleted/purge", map[string]any{"all": true}); r["deleted"] != 3.0 {
		t.Fatalf("%v", r)
	}
	if len(bin()) != 0 || len(list(c.ok("GET", "/api/deleted", nil)["objects"])) != 0 {
		t.Fatal("not empty")
	}
	initDNSBin(dir)
	if len(bin()) != 0 {
		t.Fatal("emptying was not persisted")
	}
}
