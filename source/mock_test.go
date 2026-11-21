package main

// In-memory LDAP directory used for integration tests (and, with
// ADUC_MOCK_SERVE=1, to try the UI without a Samba server).

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type mobj struct {
	dn    string
	attrs map[string][][]byte
}

func (o *mobj) vals(a string) [][]byte {
	for k, v := range o.attrs {
		if strings.EqualFold(k, a) {
			return v
		}
	}
	return nil
}
func (o *mobj) str(a string) string {
	if v := o.vals(a); len(v) > 0 {
		return string(v[0])
	}
	return ""
}
func (o *mobj) set(a string, v [][]byte) {
	for k := range o.attrs {
		if strings.EqualFold(k, a) {
			delete(o.attrs, k)
		}
	}
	if len(v) > 0 {
		o.attrs[a] = v
	}
}

type mockDC struct {
	mu  sync.Mutex
	dir map[string]*mobj // key: lower(dn)
	ln  net.Listener

	denyEnable   bool   // refuse enableOptionalFeature (not an Enterprise Admin)
	denyGPOWrite bool   // refuse modifies below CN=Policies (a user who may not edit GPOs)
	forestLvl    string // forestFunctionality to report; "" means 4 (2008 R2)
}

func (d *mockDC) put(dn string, kv ...string) *mobj {
	o := &mobj{dn: dn, attrs: map[string][][]byte{}}
	for i := 0; i < len(kv); i += 2 {
		o.attrs[kv[i]] = append(o.attrs[kv[i]], []byte(kv[i+1]))
	}
	d.dir[strings.ToLower(dn)] = o
	return o
}

const tBase = "DC=samdom,DC=example,DC=com"
const tDefaultGPO = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
const tCfg = "CN=Configuration," + tBase
const tSites = "CN=Sites," + tCfg
const tZoneC = "CN=MicrosoftDNS,DC=DomainDnsZones," + tBase
const tZone = "DC=samdom.example.com," + tZoneC
const tNTDS = "CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name," + tSites

func ft(t time.Time) string { return strconv.FormatInt(timeToFT(t), 10) }

func newMockDC(t testing.TB) *mockDC {
	d := &mockDC{dir: map[string]*mobj{}}
	d.put(tBase, "objectClass", "top", "objectClass", "domainDNS", "name", "samdom", "minPwdLength", "7", "pwdHistoryLength", "24", "maxPwdAge", "-36288000000000", "minPwdAge", "-864000000000",
		"lockoutThreshold", "0", "lockoutDuration", "-18000000000", "lockOutObservationWindow", "-18000000000", "pwdProperties", "1", "fSMORoleOwner", tNTDS,
		"gPLink", "[LDAP://CN="+tDefaultGPO+",CN=Policies,CN=System,"+tBase+";0]")
	d.put("CN=System,"+tBase, "objectClass", "container", "name", "System")
	d.put("CN=RID Manager$,CN=System,"+tBase, "objectClass", "rIDManager", "fSMORoleOwner", tNTDS)
	d.put("CN=Password Settings Container,CN=System,"+tBase, "objectClass", "msDS-PasswordSettingsContainer", "name", "Password Settings Container")
	d.put("CN=Infrastructure,"+tBase, "objectClass", "infrastructureUpdate", "fSMORoleOwner", tNTDS)
	d.put("CN=Policies,CN=System,"+tBase, "objectClass", "container", "name", "Policies")
	d.put("CN="+tDefaultGPO+",CN=Policies,CN=System,"+tBase, "objectClass", "top", "objectClass", "container", "objectClass", "groupPolicyContainer", "name", tDefaultGPO,
		"displayName", "Default Domain Policy", "flags", "0", "versionNumber", "65537", "whenCreated", "20260101120000.0Z", "whenChanged", "20260102120000.0Z",
		"gPCFileSysPath", `\\samdom.example.com\sysvol\samdom.example.com\Policies\`+tDefaultGPO)
	d.put("CN=Users,"+tBase, "objectClass", "container", "name", "Users")
	d.put("OU=Staff,"+tBase, "objectClass", "organizationalUnit", "name", "Staff")
	d.put("CN=Deleted Objects,"+tBase, "objectClass", "container", "name", "Deleted Objects", "isDeleted", "TRUE")
	d.put("CN=Deleted Objects,"+tCfg, "objectClass", "container", "name", "Deleted Objects", "isDeleted", "TRUE") // each partition has its own
	d.put(tCfg, "objectClass", "configuration", "name", "Configuration")
	d.put("CN=Schema,"+tCfg, "objectClass", "dMD", "name", "Schema", "fSMORoleOwner", tNTDS)
	d.put("CN=Partitions,"+tCfg, "objectClass", "crossRefContainer", "fSMORoleOwner", tNTDS)
	d.put(tSites, "objectClass", "sitesContainer", "name", "Sites")
	d.put("CN=Default-First-Site-Name,"+tSites, "objectClass", "site", "name", "Default-First-Site-Name")
	d.put("CN=Servers,CN=Default-First-Site-Name,"+tSites, "objectClass", "serversContainer", "name", "Servers")
	d.put("CN=DC1,CN=Servers,CN=Default-First-Site-Name,"+tSites, "objectClass", "server", "name", "DC1", "dNSHostName", "dc1.samdom.example.com")
	d.put(tNTDS, "objectClass", "nTDSDSA", "name", "NTDS Settings", "options", "1")
	d.put("CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,"+tCfg, "objectClass", "msDS-OptionalFeature", "msDS-EnabledFeatureBL", tBase)

	now := time.Now()
	old := now.AddDate(0, 0, -200)
	user := func(sam, uac, last, pwd string, extra ...string) {
		kv := append([]string{"objectClass", "user", "name", sam, "sAMAccountName", sam, "userAccountControl", uac, "pwdLastSet", pwd, "whenCreated", "20200101000000.0Z"}, extra...)
		if last != "" {
			kv = append(kv, "lastLogonTimestamp", last)
		}
		d.put("CN="+sam+",OU=Staff,"+tBase, kv...)
	}
	user("alice", "512", ft(old), ft(now.AddDate(0, 0, -40)), "memberOf", "CN=Domain Admins,CN=Users,"+tBase) // stale; password expires in 2 days
	user("bob", "514", ft(old), ft(now))                                                                      // disabled
	user("carol", "66048", ft(now), ft(now))                                                                  // never expires
	user("dave", "512", ft(now), ft(now), "lockoutTime", ft(now.Add(-5*time.Minute)))                         // locked
	user("erin", "524800", ft(now), ft(now))                                                                  // unconstrained delegation (replaces uac)
	d.put("CN=Domain Admins,CN=Users,"+tBase, "objectClass", "group", "name", "Domain Admins", "sAMAccountName", "Domain Admins", "member", "CN=alice,OU=Staff,"+tBase, "isCriticalSystemObject", "TRUE")
	d.put("CN=Nobody,CN=Users,"+tBase, "objectClass", "group", "name", "Nobody", "sAMAccountName", "Nobody")
	d.put("CN=Zed\\0ADEL:abc,CN=Deleted Objects,"+tBase, "objectClass", "user", "name", "Zed\nDEL:abc", "msDS-LastKnownRDN", "Zed", "sAMAccountName", "zed", "isDeleted", "TRUE", "lastKnownParent", "OU=Staff,"+tBase, "whenChanged", "20260101120000.0Z")

	// DNS
	rec := func(typ string, f map[string]any) string {
		b, err := encodeDNSRecord(typ, f, 3600, 5)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	d.put(tZoneC, "objectClass", "container", "name", "MicrosoftDNS")
	d.put(tZone, "objectClass", "dnsZone", "dc", "samdom.example.com")
	d.put("DC=@,"+tZone, "objectClass", "dnsNode", "dc", "@", "dnsRecord", rec("SOA", map[string]any{"serial": 5.0, "refresh": 900.0, "retry": 600.0, "expire": 86400.0, "minimum": 3600.0, "primary": "dc1.samdom.example.com", "admin": "hostmaster.samdom.example.com"}),
		"dnsRecord", rec("NS", map[string]any{"target": "dc1.samdom.example.com"}))
	d.put("DC=dc1,"+tZone, "objectClass", "dnsNode", "dc", "dc1", "dnsRecord", rec("A", map[string]any{"address": "10.0.0.2"}))
	d.put("DC=www,"+tZone, "objectClass", "dnsNode", "dc", "www", "dnsRecord", rec("CNAME", map[string]any{"target": "dc1.samdom.example.com"}))
	return d
}

func parentKey(dn string) string { return strings.ToLower(parentDN(dn)) }

func (d *mockDC) match(o *mobj, f tlv) bool {
	k, _ := parseAll(f.val)
	switch f.tag {
	case 0xa0:
		for _, x := range k {
			if !d.match(o, x) {
				return false
			}
		}
		return true
	case 0xa1:
		for _, x := range k {
			if d.match(o, x) {
				return true
			}
		}
		return false
	case 0xa2:
		return !d.match(o, k[0])
	case 0x87:
		return len(o.vals(string(f.val))) > 0
	case 0xa3:
		for _, v := range o.vals(string(k[0].val)) {
			if strings.EqualFold(string(v), string(k[1].val)) {
				return true
			}
		}
		return false
	case 0xa4:
		parts, _ := parseAll(k[1].val)
		for _, v := range o.vals(string(k[0].val)) {
			s, ok := strings.ToLower(string(v)), true
			for _, p := range parts {
				pv := strings.ToLower(string(p.val))
				switch p.tag {
				case 0x80:
					ok = ok && strings.HasPrefix(s, pv)
				case 0x82:
					ok = ok && strings.HasSuffix(s, pv)
				default:
					i := strings.Index(s, pv)
					ok = ok && i >= 0
					if i >= 0 {
						s = s[i+len(pv):]
					}
				}
			}
			if ok {
				return true
			}
		}
		return false
	case 0xa5, 0xa6:
		for _, v := range o.vals(string(k[0].val)) {
			a, e1 := strconv.ParseInt(string(v), 10, 64)
			b, e2 := strconv.ParseInt(string(k[1].val), 10, 64)
			var c int
			if e1 == nil && e2 == nil {
				c = map[bool]int{true: -1, false: 1}[a < b]
				if a == b {
					c = 0
				}
			} else {
				c = strings.Compare(string(v), string(k[1].val))
			}
			if (f.tag == 0xa5 && c >= 0) || (f.tag == 0xa6 && c <= 0) {
				return true
			}
		}
		return false
	case 0xa9:
		var rule, typ, val string
		for _, x := range k {
			switch x.tag {
			case 0x81:
				rule = string(x.val)
			case 0x82:
				typ = string(x.val)
			case 0x83:
				val = string(x.val)
			}
		}
		switch rule {
		case "1.2.840.113556.1.4.803":
			a, _ := strconv.ParseInt(o.str(typ), 10, 64)
			b, _ := strconv.ParseInt(val, 10, 64)
			return a&b == b && b != 0
		case "1.2.840.113556.1.4.1941": // in-chain: approximated by direct membership
			for _, v := range o.vals(typ) {
				if strings.EqualFold(string(v), val) {
					return true
				}
			}
		}
		return false
	}
	return false
}

func (d *mockDC) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		m, err := readTLV(r)
		if err != nil {
			return
		}
		k, _ := parseAll(m.val)
		id := k[0].val
		send := func(op []byte) { c.Write(enc(0x30, cat(enc(0x02, id), op))) }
		res := func(code int, msg string) []byte { return cat(bEnum(code), bOctet(""), bOctet(msg)) }
		showDeleted := false
		if len(k) > 2 && k[2].tag == 0xa0 {
			cs, _ := parseAll(k[2].val)
			for _, x := range cs {
				if p, _ := parseAll(x.val); len(p) > 0 && string(p[0].val) == oidShowDeleted {
					showDeleted = true
				}
			}
		}
		f, _ := parseAll(k[1].val)
		d.mu.Lock()
		switch k[1].tag {
		case 0x60:
			if mockBindNeedsUPN.Load() && len(f) > 1 && !strings.ContainsAny(string(f[1].val), "@\\=") {
				send(enc(0x61, res(49, "invalid credentials")))
			} else {
				send(enc(0x61, res(0, "")))
			}
		case 0x63:
			base, scope, max := string(f[0].val), parseInt(f[1].val), parseInt(f[3].val)
			var out []*mobj
			if base == "" {
				root := &mobj{attrs: map[string][][]byte{}}
				root.attrs["defaultNamingContext"] = [][]byte{[]byte(tBase)}
				root.attrs["rootDomainNamingContext"] = [][]byte{[]byte(tBase)}
				root.attrs["configurationNamingContext"] = [][]byte{[]byte(tCfg)}
				root.attrs["schemaNamingContext"] = [][]byte{[]byte("CN=Schema," + tCfg)}
				root.attrs["namingContexts"] = [][]byte{[]byte(tBase), []byte(tCfg), []byte("DC=DomainDnsZones," + tBase)}
				root.attrs["domainFunctionality"] = [][]byte{[]byte("4")}
				root.attrs["forestFunctionality"] = [][]byte{[]byte("4")}
				if d.forestLvl != "" {
					root.attrs["forestFunctionality"] = [][]byte{[]byte(d.forestLvl)}
				}
				root.attrs["dnsHostName"] = [][]byte{[]byte("dc1.samdom.example.com")}
				out = append(out, root)
			} else {
				bl := strings.ToLower(base)
				for key, o := range d.dir {
					ok := false
					switch scope {
					case 0:
						ok = key == bl
					case 1:
						ok = parentKey(o.dn) == bl
					default:
						ok = key == bl || strings.HasSuffix(key, ","+bl)
					}
					if ok && o.str("isDeleted") == "TRUE" && !showDeleted {
						ok = false
					}
					// like a real DC, a search of the domain partition does not reach into the Configuration partition
					if ok && bl == strings.ToLower(tBase) && strings.HasSuffix(key, strings.ToLower(tCfg)) {
						ok = false
					}
					if ok && d.match(o, f[6]) {
						out = append(out, o)
					}
				}
			}
			code := 0
			for i, o := range out {
				if max > 0 && i >= max {
					code = 4
					break
				}
				var al []byte
				for a, vs := range o.attrs {
					var v []byte
					for _, x := range vs {
						v = append(v, bOctetB(x)...)
					}
					al = append(al, enc(0x30, cat(bOctet(a), enc(0x31, v)))...)
				}
				send(enc(0x64, cat(bOctet(o.dn), enc(0x30, al))))
			}
			c.Write(enc(0x30, cat(enc(0x02, id), enc(0x65, res(code, "")), enc(0xa0, control(oidPaged, false, enc(0x30, cat(bInt(0), bOctetB(nil))))))))
		case 0x66:
			if string(f[0].val) == "" { // rootDSE: enableOptionalFeature, as Samba implements it
				ml, _ := parseAll(f[1].val)
				code, msg := 0, ""
				for _, mm := range ml {
					p, _ := parseAll(mm.val)
					pa, _ := parseAll(p[1].val)
					vs, _ := parseAll(pa[1].val)
					if !strings.EqualFold(string(pa[0].val), "enableOptionalFeature") || len(vs) != 1 {
						code, msg = 53, "unsupported rootDSE modify"
						continue
					}
					if string(vs[0].val) != "CN=Partitions,"+tCfg+":766ddcd8-acd0-445e-f3b9-a7f9b6744f2a" {
						code, msg = 53, "unknown optional feature"
						continue
					}
					if d.denyEnable {
						code, msg = 50, "insufficient access"
						continue
					}
					feat := "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services," + tCfg
					d.dir[strings.ToLower(feat)].set("msDS-EnabledFeatureBL", [][]byte{[]byte(tBase)})
					d.dir[strings.ToLower("CN=Partitions,"+tCfg)].set("msDS-EnabledFeature", [][]byte{[]byte(feat)})
				}
				send(enc(0x67, res(code, msg)))
				break
			}
			o := d.dir[strings.ToLower(string(f[0].val))]
			if o == nil {
				send(enc(0x67, res(32, "no such object")))
				break
			}
			if d.denyGPOWrite && strings.Contains(strings.ToLower(o.dn), ",cn=policies,cn=system,") {
				send(enc(0x67, res(50, "insufficient access")))
				break
			}
			ml, _ := parseAll(f[1].val)
			code, msg := 0, ""
			type change struct {
				op   int
				attr string
				vals [][]byte
			}
			var changes []change
			for _, mm := range ml {
				p, _ := parseAll(mm.val)
				pa, _ := parseAll(p[1].val)
				vs, _ := parseAll(pa[1].val)
				var vals [][]byte
				for _, v := range vs {
					vals = append(vals, v.val)
				}
				changes = append(changes, change{parseInt(p[0].val), string(pa[0].val), vals})
			}
			for _, ch := range changes {
				switch {
				case strings.EqualFold(ch.attr, "distinguishedName") && ch.op == 0:
					nd := string(ch.vals[0])
					delete(d.dir, strings.ToLower(o.dn))
					o.dn = nd
					o.set("name", [][]byte{[]byte(strings.TrimPrefix(firstRDN(nd), firstRDN(nd)[:strings.Index(firstRDN(nd), "=")+1]))})
					d.dir[strings.ToLower(nd)] = o
				case ch.op == 0:
					if strings.EqualFold(ch.attr, "member") {
						for _, e := range o.vals("member") {
							if string(e) == string(ch.vals[0]) {
								code, msg = 20, "exists"
							}
						}
					}
					if code == 0 {
						o.attrs[ch.attr] = append(o.attrs[ch.attr], ch.vals...)
					}
				case ch.op == 1:
					if len(ch.vals) == 0 {
						o.set(ch.attr, nil)
						continue
					}
					var keep [][]byte
					found := false
					for _, e := range o.vals(ch.attr) {
						if string(e) == string(ch.vals[0]) {
							found = true
							continue
						}
						keep = append(keep, e)
					}
					if !found {
						code, msg = 16, "no such value"
					}
					o.set(ch.attr, keep)
				case ch.op == 2:
					if strings.EqualFold(ch.attr, "unicodePwd") {
						continue
					}
					o.set(ch.attr, ch.vals)
				}
			}
			send(enc(0x67, res(code, msg)))
		case 0x68:
			dn := string(f[0].val)
			if d.dir[strings.ToLower(dn)] != nil {
				send(enc(0x69, res(68, "exists")))
				break
			}
			if d.dir[parentKey(dn)] == nil {
				send(enc(0x69, res(32, "no parent")))
				break
			}
			o := &mobj{dn: dn, attrs: map[string][][]byte{}}
			al, _ := parseAll(f[1].val)
			for _, a := range al {
				p, _ := parseAll(a.val)
				vs, _ := parseAll(p[1].val)
				for _, v := range vs {
					o.attrs[string(p[0].val)] = append(o.attrs[string(p[0].val)], v.val)
				}
			}
			rdn := firstRDN(dn)
			o.attrs["name"] = [][]byte{[]byte(rdn[strings.Index(rdn, "=")+1:])}
			d.dir[strings.ToLower(dn)] = o
			send(enc(0x69, res(0, "")))
		case 0x4a:
			del := strings.ToLower(string(k[1].val))
			if d.dir[del] == nil {
				send(enc(0x6b, res(32, "no such object")))
				break
			}
			if mockRefusePurge.Load() && d.dir[del].str("isDeleted") == "TRUE" { // like AD: a deleted object cannot be deleted over LDAP
				send(enc(0x6b, res(53, "unwilling to perform")))
				break
			}
			for key := range d.dir {
				if strings.HasSuffix(key, ","+del) {
					delete(d.dir, key)
				}
			}
			o := d.dir[del]
			delete(d.dir, del)
			// like a DC with the Recycle Bin feature on: a delete in the domain keeps the object in Deleted Objects
			fo := d.dir[strings.ToLower("CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,"+tCfg)]
			if fo != nil && len(fo.attrs["msDS-EnabledFeatureBL"]) > 0 && strings.HasSuffix(del, strings.ToLower(tBase)) && o.str("isDeleted") != "TRUE" {
				rdn := firstRDN(string(k[1].val))
				nm := rdn[strings.Index(rdn, "=")+1:]
				o.attrs["isDeleted"] = [][]byte{[]byte("TRUE")}
				o.attrs["msDS-LastKnownRDN"] = [][]byte{[]byte(nm)}
				o.attrs["lastKnownParent"] = [][]byte{[]byte(parentDN(string(k[1].val)))}
				o.attrs["name"] = [][]byte{[]byte(nm + "\nDEL:" + fmt.Sprint(len(d.dir)))}
				cont := "CN=Deleted Objects," + tBase
				if strings.HasSuffix(del, strings.ToLower(tCfg)) { // Configuration objects go to that partition's own container
					cont = "CN=Deleted Objects," + tCfg
				}
				o.dn = "CN=" + nm + "\\0ADEL:" + fmt.Sprint(len(d.dir)) + "," + cont
				d.dir[strings.ToLower(o.dn)] = o
			}
			send(enc(0x6b, res(0, "")))
		case 0x6c:
			dn, rdn := string(f[0].val), string(f[1].val)
			o := d.dir[strings.ToLower(dn)]
			np := parentDN(dn)
			if len(f) > 3 {
				np = string(f[3].val)
			}
			if o == nil {
				send(enc(0x6d, res(32, "no such object")))
				break
			}
			delete(d.dir, strings.ToLower(dn))
			o.dn = rdn + "," + np
			d.dir[strings.ToLower(o.dn)] = o
			send(enc(0x6d, res(0, "")))
		}
		d.mu.Unlock()
	}
}

func (d *mockDC) start(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		panic(err)
	}
	d.ln = ln
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go d.serve(c)
		}
	}()
}

// ---- tiny HTTP client for the tests ----

type tc struct {
	t   *testing.T
	srv *httptest.Server
	cl  *http.Client
}

func (c *tc) call(method, path string, body any) (int, map[string]any) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, rd)
	req.Header.Set("X-Requested-With", "aduc")
	resp, err := c.cl.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (c *tc) ok(method, path string, body any) map[string]any {
	c.t.Helper()
	code, out := c.call(method, path, body)
	if code != 200 {
		c.t.Fatalf("%s %s -> %d %v", method, path, code, out)
	}
	return out
}

func (c *tc) fail(method, path string, body any, want string) {
	c.t.Helper()
	code, out := c.call(method, path, body)
	if code == 200 || !strings.Contains(fmt.Sprint(out["error"]), want) {
		c.t.Fatalf("%s %s -> %d %v (want error containing %q)", method, path, code, out, want)
	}
}

func setup(t *testing.T) (*tc, *mockDC) {
	d := newMockDC(t)
	d.start("127.0.0.1:0")
	cfg = Config{URL: "ldap://" + d.ln.Addr().String()}
	srv := httptest.NewServer(securityHeaders(buildMux()))
	jar, _ := cookiejar.New(nil)
	c := &tc{t, srv, &http.Client{Jar: jar}}
	t.Cleanup(func() { srv.Close(); d.ln.Close() })
	out := c.ok("POST", "/api/login", map[string]string{"username": "admin@samdom.example.com", "password": "secret"})
	// the UI needs the naming contexts and the schema DN right after sign-in (other-NC roots, schema search)
	if len(list(out["ncs"])) != 3 || out["schema"] != "CN=Schema,"+tCfg {
		t.Fatalf("login response: %v", out)
	}
	return c, d
}

func list(v any) []any { l, _ := v.([]any); return l }
func names(rows any, key string) string {
	var out []string
	for _, r := range list(rows) {
		out = append(out, fmt.Sprint(r.(map[string]any)[key]))
	}
	return strings.Join(out, ",")
}

func TestMockServe(t *testing.T) { // ADUC_MOCK_SERVE=1 go test -run TestMockServe -timeout 0
	if os.Getenv("ADUC_MOCK_SERVE") == "" {
		t.Skip()
	}
	d := newMockDC(t)
	root := mockSysvol(t)
	sysvolRoot = root
	t.Logf("mock SYSVOL in %s", root)
	if os.Getenv("ADUC_MOCK_RB") == "off" { // start with the Recycle Bin disabled, like a fresh Samba domain
		delete(d.dir[strings.ToLower("CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,"+tCfg)].attrs, "msDS-EnabledFeatureBL")
	}
	// the signed-in user may be anyone; make "administrator" a Domain Admin so Settings (Update, Certificate) can be tried
	d.put("CN=Administrator,CN=Users,"+tBase, "objectClass", "top", "objectClass", "person", "objectClass", "user", "sAMAccountName", "administrator",
		"userPrincipalName", "administrator@samdom.example.com", "memberOf", "CN=Domain Admins,CN=Users,"+tBase)
	if err := webCert.initAuto(filepath.Join(t.TempDir(), "tls")); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("ADUC_MOCK_PEERS") != "" { // a DC that refuses to purge, and a second DC with its own goaduc, to try the Recycle Bin dialog
		mockRefusePurge.Store(true)
		samDB, samDBUsable = "/mock/sam.ldb", func() bool { return true }
		wipe := func(only string) {
			d.mu.Lock()
			defer d.mu.Unlock()
			for k, o := range d.dir {
				if o.str("isDeleted") == "TRUE" && strings.Contains(k, ",cn=deleted objects,") && (only == "" || strings.EqualFold(only, o.dn)) {
					delete(d.dir, k)
				}
			}
		}
		sambaToolRun = func(args ...string) error { wipe(""); return nil }
		ldbDelLocal = func(dn string) error { wipe(dn); return nil }
		d.put("CN=DC2,CN=Servers,CN=Default-First-Site-Name,"+tSites, "objectClass", "server", "name", "DC2", "dNSHostName", "dc2.samdom.example.com")
		d.put("CN=NTDS Settings,CN=DC2,CN=Servers,CN=Default-First-Site-Name,"+tSites, "objectClass", "nTDSDSA", "name", "NTDS Settings", "options", "0")
		peer := newFakePeer(t)
		_, port, _ := net.SplitHostPort(peer.srv.Listener.Addr().String())
		peerAddr = func(host string) string { return net.JoinHostPort("127.0.0.1", port) }
	}
	d.start("127.0.0.1:3389")
	cfg = Config{URL: "ldap://127.0.0.1:3389"}
	http.ListenAndServe("127.0.0.1:8099", securityHeaders(buildMux()))
}

// ---- integration tests ----

func TestDomainInfoAndPolicy(t *testing.T) {
	c, _ := setup(t)
	di := c.ok("GET", "/api/domaininfo", nil)
	if names(di["fsmo"], "server") != "DC1,DC1,DC1,DC1,DC1" || di["recycleBin"] != true {
		t.Fatalf("%v", di)
	}
	dcs := list(di["dcs"])
	if len(dcs) != 1 || dcs[0].(map[string]any)["gc"] != true || dcs[0].(map[string]any)["dns"] != "dc1.samdom.example.com" {
		t.Fatalf("%v", dcs)
	}
	p := c.ok("GET", "/api/policy", nil)
	if p["minLength"] != 7.0 || p["maxAgeDays"] != 42.0 || p["minAgeDays"] != 1.0 || p["durationMin"] != 30.0 || p["complexity"] != true {
		t.Fatalf("%v", p)
	}
	c.ok("PUT", "/api/policy", map[string]any{"minLength": 12, "history": 10, "maxAgeDays": 0, "minAgeDays": 0, "threshold": 5, "durationMin": 15, "windowMin": 10, "complexity": true, "reversible": false})
	p = c.ok("GET", "/api/policy", nil)
	if p["minLength"] != 12.0 || p["maxAgeDays"] != 0.0 || p["threshold"] != 5.0 || p["durationMin"] != 15.0 {
		t.Fatalf("%v", p)
	}
	c.fail("PUT", "/api/policy", map[string]any{"minLength": 12, "threshold": 5, "windowMin": 0}, "observation window")
}

func TestLoginWithSamAccountName(t *testing.T) {
	c, _ := setup(t)
	mockBindNeedsUPN.Store(true)
	defer mockBindNeedsUPN.Store(false)
	// a server that only accepts UPN/DN binds: the bare logon name is retried as name@realm
	out := c.ok("POST", "/api/login", map[string]string{"username": "administrator", "password": "secret"})
	if out["user"] != "administrator@samdom.example.com" {
		t.Fatalf("%v", out)
	}
	c.ok("GET", "/api/domaininfo", nil)
	// forms that already carry a realm or domain are sent as typed, so a refusal stays a refusal
	mockBindNeedsUPN.Store(false)
	out = c.ok("POST", "/api/login", map[string]string{"username": "SAMDOM\\administrator", "password": "secret"})
	if out["user"] != "SAMDOM\\administrator" {
		t.Fatalf("%v", out)
	}
}

func TestUPNSuffixes(t *testing.T) {
	c, _ := setup(t)
	if l := c.ok("GET", "/api/upnsuffixes", nil)["suffixes"].([]any); len(l) != 0 {
		t.Fatalf("%v", l)
	}
	r := c.ok("PUT", "/api/upnsuffixes", map[string]any{"suffixes": []string{"@Example.org", " corp.example.net ", "example.org"}})
	if l := r["suffixes"].([]any); len(l) != 2 || l[0] != "corp.example.net" || l[1] != "example.org" {
		t.Fatalf("%v", l)
	}
	if l := c.ok("GET", "/api/upnsuffixes", nil)["suffixes"].([]any); len(l) != 2 {
		t.Fatalf("%v", l)
	}
	c.fail("PUT", "/api/upnsuffixes", map[string]any{"suffixes": []string{"bad name"}}, "not a valid")
	c.fail("PUT", "/api/upnsuffixes", map[string]any{"suffixes": []string{"-bad.example"}}, "not a valid")
	c.ok("PUT", "/api/upnsuffixes", map[string]any{"suffixes": []string{"local"}})
	c.fail("PUT", "/api/upnsuffixes", map[string]any{"suffixes": []string{"samdom.example.com"}}, "own suffix")
	c.ok("PUT", "/api/upnsuffixes", map[string]any{"suffixes": []string{}})
	if l := c.ok("GET", "/api/upnsuffixes", nil)["suffixes"].([]any); len(l) != 0 {
		t.Fatalf("%v", l)
	}
}

func TestPSO(t *testing.T) {
	c, _ := setup(t)
	body := map[string]any{"name": "Admins-PSO", "precedence": 10, "minLength": 14, "history": 24, "maxAgeDays": 30, "minAgeDays": 1, "threshold": 3, "durationMin": 30, "windowMin": 30, "complexity": true, "reversible": false, "appliesTo": []string{"CN=Domain Admins,CN=Users," + tBase}}
	c.ok("POST", "/api/pso/save", body)
	l := list(c.ok("GET", "/api/pso", nil)["psos"])
	if len(l) != 1 {
		t.Fatal(l)
	}
	p := l[0].(map[string]any)
	if p["name"] != "Admins-PSO" || p["minLength"] != 14.0 || p["maxAgeDays"] != 30.0 || p["threshold"] != 3.0 || len(list(p["appliesTo"])) != 1 {
		t.Fatalf("%v", p)
	}
	body["dn"], body["minLength"], body["appliesTo"] = p["dn"], 16, []string{}
	c.ok("POST", "/api/pso/save", body)
	p = list(c.ok("GET", "/api/pso", nil)["psos"])[0].(map[string]any)
	if p["minLength"] != 16.0 || len(list(p["appliesTo"])) != 0 {
		t.Fatalf("%v", p)
	}
	body["precedence"] = 0
	c.fail("POST", "/api/pso/save", body, "precedence")
	c.fail("POST", "/api/pso/save", map[string]any{"dn": "CN=x,OU=Staff," + tBase, "precedence": 1, "name": "x"}, "not a password settings object")
}

func TestReports(t *testing.T) {
	c, _ := setup(t)
	rep := func(n string) string {
		return names(c.ok("GET", "/api/report?name="+n+"&days=90", nil)["rows"], "name")
	}
	for name, want := range map[string]string{
		"stale-users": "alice", "disabled": "bob", "never-expire": "carol", "locked": "dave", "unconstrained": "erin",
		"privileged": "alice", "empty-groups": "Nobody", "no-preauth": "",
	} {
		if got := rep(name); got != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
	if got := names(c.ok("GET", "/api/report?name=expiring&days=7", nil)["rows"], "name"); got != "alice" { // 42-day max age, set 40 days ago
		t.Errorf("expiring: %q", got)
	}
	c.fail("GET", "/api/report?name=bogus", nil, "unknown report")
}

func TestDeleteGoesToRecycleBin(t *testing.T) {
	c, d := setup(t)
	if r := c.ok("GET", "/api/recyclebin", nil); r["enabled"] != true || r["known"] != true {
		t.Fatalf("%v", r)
	}
	victim := "CN=alice,OU=Staff," + tBase
	c.ok("POST", "/api/delete", map[string]any{"dn": victim})
	var dn string
	for _, o := range list(c.ok("GET", "/api/deleted", nil)["objects"]) {
		if m := o.(map[string]any); m["name"] == "alice" {
			dn = m["dn"].(string)
		}
	}
	if dn == "" {
		t.Fatal("deleted user is not in the Recycle Bin")
	}
	c.ok("POST", "/api/deleted/restore", map[string]any{"dn": dn, "parent": "OU=Staff," + tBase, "name": "alice", "type": "user"})
	d.mu.Lock()
	o := d.dir[strings.ToLower(victim)]
	d.mu.Unlock()
	if o == nil || o.str("isDeleted") != "" {
		t.Fatal("not restored")
	}
	// feature off: the same status call says so, and a delete is final
	fd := strings.ToLower("CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services," + tCfg)
	d.mu.Lock()
	delete(d.dir[fd].attrs, "msDS-EnabledFeatureBL")
	d.mu.Unlock()
	if r := c.ok("GET", "/api/recyclebin", nil); r["enabled"] != false {
		t.Fatalf("%v", r)
	}
	c.ok("POST", "/api/delete", map[string]any{"dn": "CN=bob,OU=Staff," + tBase})
	for _, o := range list(c.ok("GET", "/api/deleted", nil)["objects"]) {
		if o.(map[string]any)["name"] == "bob" {
			t.Fatal("recycled although the feature is off")
		}
	}
}

var mockBindNeedsUPN atomic.Bool

var mockRefusePurge atomic.Bool

func TestPurgeLocalFallback(t *testing.T) {
	c, d := setup(t)
	mockRefusePurge.Store(true)
	osam, ostool, oldb, ousable := samDB, sambaToolRun, ldbDelLocal, samDBUsable
	t.Cleanup(func() {
		mockRefusePurge.Store(false)
		samDB, sambaToolRun, ldbDelLocal, samDBUsable = osam, ostool, oldb, ousable
	})
	samDB = "/scratch/sam.ldb"
	var toolArgs []string
	var delDNs []string
	wipe := func(only string) { // what the local tools do to the mock directory
		d.mu.Lock()
		for k, o := range d.dir {
			if o.str("isDeleted") == "TRUE" && strings.Contains(k, ",cn=deleted objects,") && (only == "" || strings.EqualFold(only, o.dn)) {
				delete(d.dir, k)
			}
		}
		d.mu.Unlock()
	}
	sambaToolRun = func(args ...string) error { toolArgs = args; wipe(""); return nil }
	ldbDelLocal = func(dn string) error { delDNs = append(delDNs, dn); wipe(dn); return nil }
	c.ok("POST", "/api/delete", map[string]any{"dn": "CN=alice,OU=Staff," + tBase})
	bin := func() []any { return list(c.ok("GET", "/api/deleted", nil)["objects"]) }
	if len(bin()) != 2 {
		t.Fatalf("%v", bin())
	}
	one := bin()[0].(map[string]any)["dn"].(string)

	// refused, and no root / sam.ldb: the refusal is shown, nothing runs
	samDBUsable = func() bool { return false }
	c.fail("POST", "/api/deleted/purge", map[string]any{"dn": one}, "unwilling")
	c.fail("POST", "/api/deleted/purge", map[string]any{"all": true}, "unwilling")
	// root, but the signed-in user is not a Domain/Enterprise Admin: still nothing runs
	samDBUsable = func() bool { return true }
	c.fail("POST", "/api/deleted/purge", map[string]any{"dn": one}, "only a Domain Admin")
	c.fail("POST", "/api/deleted/purge", map[string]any{"all": true}, "only a Domain Admin")
	if len(toolArgs) != 0 || len(delDNs) != 0 || len(bin()) != 2 {
		t.Fatal("the fallback ran without its conditions")
	}
	// a refusal that is not a refusal (no such object) never reaches the fallback
	c.fail("POST", "/api/deleted/purge", map[string]any{"dn": "CN=ghost\\0ADEL:1,CN=Deleted Objects," + tBase}, "no such object")
	if len(delDNs) != 0 {
		t.Fatal("fallback ran for a missing object")
	}
	// make the user a Domain Admin
	d.mu.Lock()
	d.put("CN=admin,CN=Users,"+tBase, "objectClass", "top", "objectClass", "person", "objectClass", "user", "sAMAccountName", "admin",
		"userPrincipalName", "admin@samdom.example.com", "memberOf", "CN=Domain Admins,CN=Users,"+tBase)
	d.mu.Unlock()
	// without local=true the page is asked first and nothing runs (the removal is not replicated)
	if r := c.ok("POST", "/api/deleted/purge", map[string]any{"dn": one}); r["needsLocal"] != true || r["server"] != "dc1.samdom.example.com" {
		t.Fatalf("%v", r)
	}
	if len(toolArgs) != 0 || len(delDNs) != 0 || len(bin()) != 2 {
		t.Fatal("the fallback ran without being agreed to")
	}
	// a failing local tool is reported and changes nothing
	ldbDelLocal = func(dn string) error { return errors.New("boom") }
	c.fail("POST", "/api/deleted/purge", map[string]any{"dn": one, "local": true}, "local fallback failed: boom")
	ldbDelLocal = func(dn string) error { delDNs = append(delDNs, dn); wipe(dn); return nil }
	if len(bin()) != 2 {
		t.Fatal("a failed fallback changed the bin")
	}
	// one object, locally
	if r := c.ok("POST", "/api/deleted/purge", map[string]any{"dn": one, "local": true}); r["deleted"] != 1.0 {
		t.Fatal(r)
	}
	if len(delDNs) != 1 || delDNs[0] != one || len(bin()) != 1 {
		t.Fatalf("%v %v", delDNs, bin())
	}
	// everything, locally: samba-tool expunge with a zero lifetime against -sam-db
	if r := c.ok("POST", "/api/deleted/purge", map[string]any{"all": true, "local": true}); r["deleted"] != 1.0 {
		t.Fatal(r)
	}
	if strings.Join(toolArgs, " ") != "domain tombstones expunge --tombstone-lifetime=0 -H /scratch/sam.ldb" || len(bin()) != 0 {
		t.Fatalf("%v %v", toolArgs, bin())
	}
	// an expunge that leaves objects behind is not reported as success
	c.ok("POST", "/api/delete", map[string]any{"dn": "CN=bob,OU=Staff," + tBase})
	sambaToolRun = func(args ...string) error { return nil }
	c.fail("POST", "/api/deleted/purge", map[string]any{"all": true, "local": true}, "left 1 of 1")
}

func TestConfigurationDeletesGoToTheBin(t *testing.T) {
	c, d := setup(t)
	sites := "CN=Sites," + tCfg
	site := "CN=Default-First-Site-Name," + sites
	d.mu.Lock()
	if d.dir[strings.ToLower(site)] == nil {
		d.put(site, "objectClass", "site", "name", "Default-First-Site-Name")
	}
	if d.dir[strings.ToLower("CN=Subnets,"+sites)] == nil {
		d.put("CN=Subnets,"+sites, "objectClass", "container", "name", "Subnets")
	}
	d.mu.Unlock()
	c.ok("POST", "/api/sites/create", map[string]any{"kind": "subnet", "name": "10.9.0.0/24", "site": site})
	sub := "CN=10.9.0.0/24,CN=Subnets," + sites
	c.ok("POST", "/api/delete", map[string]any{"dn": sub})
	var got map[string]any
	for _, o := range list(c.ok("GET", "/api/deleted", nil)["objects"]) {
		if m := o.(map[string]any); m["name"] == "10.9.0.0/24" {
			got = m
		}
	}
	if got == nil || got["type"] != "subnet" || !strings.HasSuffix(got["dn"].(string), "CN=Deleted Objects,"+tCfg) {
		t.Fatalf("deleted subnet is not in the bin: %v", got)
	}
	if n := 0; true {
		for _, o := range list(c.ok("GET", "/api/deleted", nil)["objects"]) {
			if o.(map[string]any)["name"] == "10.9.0.0/24" {
				n++
			}
		}
		if n != 1 {
			t.Fatalf("listed %d times", n)
		}
	}
	c.ok("POST", "/api/deleted/restore", map[string]any{"dn": got["dn"], "parent": "CN=Subnets," + sites, "name": "10.9.0.0/24", "type": "subnet"})
	d.mu.Lock()
	o := d.dir[strings.ToLower(sub)]
	d.mu.Unlock()
	if o == nil || o.str("isDeleted") != "" {
		t.Fatal("subnet not restored")
	}
}

func TestPurgeRecycleBin(t *testing.T) {
	c, d := setup(t)
	c.ok("POST", "/api/delete", map[string]any{"dn": "CN=alice,OU=Staff," + tBase})
	l := list(c.ok("GET", "/api/deleted", nil)["objects"])
	if len(l) != 2 {
		t.Fatalf("%v", l)
	}
	c.fail("POST", "/api/deleted/purge", map[string]any{"dn": "CN=bob,OU=Staff," + tBase}, "not an object in the Recycle Bin")
	c.fail("POST", "/api/deleted/purge", map[string]any{"dn": "CN=x,CN=Deleted Objects,DC=other,DC=com"}, "")
	one := l[0].(map[string]any)["dn"].(string)
	if r := c.ok("POST", "/api/deleted/purge", map[string]any{"dn": one}); r["deleted"] != 1.0 {
		t.Fatal(r)
	}
	if l := list(c.ok("GET", "/api/deleted", nil)["objects"]); len(l) != 1 {
		t.Fatalf("%v", l)
	}
	if r := c.ok("POST", "/api/deleted/purge", map[string]any{"all": true}); r["deleted"] != 1.0 {
		t.Fatal(r)
	}
	if l := list(c.ok("GET", "/api/deleted", nil)["objects"]); len(l) != 0 {
		t.Fatalf("%v", l)
	}
	d.mu.Lock()
	n := len(d.dir)
	d.mu.Unlock()
	if n == 0 {
		t.Fatal("emptied the whole directory")
	}
}

func TestRecycleBin(t *testing.T) {
	c, d := setup(t)
	l := list(c.ok("GET", "/api/deleted", nil)["objects"])
	if len(l) != 1 || l[0].(map[string]any)["name"] != "Zed" || l[0].(map[string]any)["sam"] != "zed" {
		t.Fatalf("%v", l)
	}
	dn := l[0].(map[string]any)["dn"].(string)
	c.fail("POST", "/api/deleted/restore", map[string]any{"dn": dn, "parent": "OU=Nope," + tBase, "name": "Zed", "type": "user"}, "destination container")
	r := c.ok("POST", "/api/deleted/restore", map[string]any{"dn": dn, "parent": "OU=Staff," + tBase, "name": "Zed", "type": "user"})
	if r["dn"] != "CN=Zed,OU=Staff,"+tBase {
		t.Fatal(r)
	}
	d.mu.Lock()
	o := d.dir[strings.ToLower("CN=Zed,OU=Staff,"+tBase)]
	d.mu.Unlock()
	if o == nil || o.str("isDeleted") != "" {
		t.Fatal("not restored")
	}
	if l := list(c.ok("GET", "/api/deleted", nil)["objects"]); len(l) != 0 {
		t.Fatal(l)
	}
}

func TestDNS(t *testing.T) {
	c, d := setup(t)
	z := list(c.ok("GET", "/api/dns/zones", nil)["zones"])
	if len(z) != 1 || z[0].(map[string]any)["name"] != "samdom.example.com" || z[0].(map[string]any)["scope"] != "Domain" {
		t.Fatalf("%v", z)
	}
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
	r := recs()
	if len(r["@"]) != 2 || r["dc1"][0]["text"] != "10.0.0.2" || r["www"][0]["type"] != "CNAME" {
		t.Fatalf("%v", r)
	}
	soaSerial := func() float64 {
		for _, x := range recs()["@"] {
			if x["type"] == "SOA" {
				return x["fields"].(map[string]any)["serial"].(float64)
			}
		}
		return -1
	}
	before := soaSerial()
	// create a new node, add a second A record, edit it, delete it
	c.ok("POST", "/api/dns/save", map[string]any{"zone": zone, "name": "web1", "type": "A", "ttl": 600, "fields": map[string]any{"address": "10.0.0.50"}})
	c.ok("POST", "/api/dns/save", map[string]any{"zone": zone, "name": "web1", "type": "A", "fields": map[string]any{"address": "10.0.0.51"}})
	r = recs()
	if len(r["web1"]) != 2 || r["web1"][0]["ttl"] != 600.0 || soaSerial() != before+2 {
		t.Fatalf("%v serial %v->%v", r["web1"], before, soaSerial())
	}
	old := r["web1"][0]["raw"].(string)
	c.ok("POST", "/api/dns/save", map[string]any{"zone": zone, "name": "web1", "old": old, "type": "A", "ttl": 120, "fields": map[string]any{"address": "10.0.0.99"}})
	r = recs()
	if len(r["web1"]) != 2 || (r["web1"][0]["text"] != "10.0.0.99" && r["web1"][1]["text"] != "10.0.0.99") {
		t.Fatalf("%v", r["web1"])
	}
	c.fail("POST", "/api/dns/save", map[string]any{"zone": zone, "name": "web1", "old": old, "type": "A", "fields": map[string]any{"address": "10.0.0.1"}}, "changed since")
	c.fail("POST", "/api/dns/save", map[string]any{"zone": zone, "name": "web1", "type": "CNAME", "fields": map[string]any{"target": "x.example.com"}}, "CNAME")
	c.fail("POST", "/api/dns/save", map[string]any{"zone": zone, "name": "www", "type": "A", "fields": map[string]any{"address": "10.0.0.1"}}, "CNAME")
	c.fail("POST", "/api/dns/save", map[string]any{"zone": zone, "name": "x", "type": "A", "fields": map[string]any{"address": "nope"}}, "IPv4")
	for _, x := range r["web1"] {
		c.ok("POST", "/api/dns/delete", map[string]any{"zone": zone, "name": "web1", "old": x["raw"]})
	}
	d.mu.Lock()
	gone := d.dir[strings.ToLower("DC=web1,"+zone)] == nil
	d.mu.Unlock()
	if !gone {
		t.Fatal("empty node should be deleted")
	}
	// editing the SOA directly does not bump the serial
	var soa map[string]any
	for _, x := range recs()["@"] {
		if x["type"] == "SOA" {
			soa = x
		}
	}
	f := soa["fields"].(map[string]any)
	f["refresh"] = 1200.0
	cur := soaSerial()
	c.ok("POST", "/api/dns/save", map[string]any{"zone": zone, "name": "@", "old": soa["raw"], "type": "SOA", "ttl": 3600, "fields": f})
	if soaSerial() != cur {
		t.Fatal("SOA edit must keep the serial the admin supplied")
	}
	c.fail("GET", "/api/dns/records?zone=CN=Users,"+tBase, nil, "not a DNS zone")
	c.fail("POST", "/api/dns/save", map[string]any{"zone": "OU=Staff," + tBase, "name": "a", "type": "A", "fields": map[string]any{"address": "1.1.1.1"}}, "not a DNS zone")
}

func TestAuditAndLogonHours(t *testing.T) {
	c, _ := setup(t)
	alice := "CN=alice,OU=Staff," + tBase
	c.ok("POST", "/api/password", map[string]any{"dn": alice, "password": "Sup3rSecret!", "mustChange": true})
	hours := make([]byte, 21)
	for i := range hours {
		hours[i] = 0xff
	}
	hours[0] = 0
	c.ok("PUT", "/api/object", map[string]any{"dn": alice, "bin": map[string][]string{"logonHours": {base64.StdEncoding.EncodeToString(hours)}}})
	o := c.ok("GET", "/api/object?dn="+alice, nil)
	if lh := list(o["attrs"].(map[string]any)["logonHours"]); len(lh) != 1 || !strings.HasPrefix(lh[0].(string), "00ffff") || len(lh[0].(string)) != 42 {
		t.Fatalf("%v", lh)
	}
	c.fail("PUT", "/api/object", map[string]any{"dn": alice, "bin": map[string][]string{"logonHours": {base64.StdEncoding.EncodeToString([]byte("short"))}}}, "21 bytes")
	c.fail("PUT", "/api/object", map[string]any{"dn": alice, "bin": map[string][]string{"objectSid": {"AAAA"}}}, "cannot be set as binary")
	a := c.ok("GET", "/api/audit", nil)
	all, _ := json.Marshal(a)
	if strings.Contains(string(all), "Sup3rSecret") || !strings.Contains(string(all), `"action":"password"`) || !strings.Contains(string(all), `"action":"login"`) {
		t.Fatalf("%s", all)
	}
	// unauthenticated and CSRF protections
	req, _ := http.NewRequest("GET", c.srv.URL+"/api/audit", nil)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Fatal("audit must need a session")
	}
}

func TestRecycleBinEnable(t *testing.T) {
	c, d := setup(t)
	feat := "cn=recycle bin feature,cn=optional features,cn=directory service,cn=windows nt,cn=services," + strings.ToLower(tCfg)
	d.mu.Lock()
	delete(d.dir[feat].attrs, "msDS-EnabledFeatureBL") // the mock starts with it enabled
	d.mu.Unlock()
	rb := func() any { return c.ok("GET", "/api/domaininfo", nil)["recycleBin"] }
	if rb() != false {
		t.Fatalf("want not enabled, got %v", rb())
	}
	d.mu.Lock()
	d.forestLvl = "3" // 2008
	d.mu.Unlock()
	c.fail("POST", "/api/recyclebin/enable", map[string]any{}, "forest functional level")
	d.mu.Lock()
	d.forestLvl, d.denyEnable = "", true
	d.mu.Unlock()
	c.fail("POST", "/api/recyclebin/enable", map[string]any{}, "insufficient access")
	if rb() != false {
		t.Fatal("a refused enable must change nothing")
	}
	// Samba refuses the remote request even for admins: the local fallback runs only as root, with the database
	// present, and only for a verified Enterprise Admin.
	calls := 0
	oldMod, oldUse := ldbModifyLocal, samDBUsable
	t.Cleanup(func() { ldbModifyLocal, samDBUsable = oldMod, oldUse })
	okStub := func(val string) error {
		calls++
		if val != "CN=Partitions,"+tCfg+":766ddcd8-acd0-445e-f3b9-a7f9b6744f2a" {
			t.Errorf("bad value %q", val)
		}
		fd := "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services," + tCfg
		d.mu.Lock()
		d.dir[strings.ToLower(fd)].set("msDS-EnabledFeatureBL", [][]byte{[]byte(tBase)})
		d.mu.Unlock()
		return nil
	}
	ldbModifyLocal = okStub
	samDBUsable = func() bool { return false }
	c.fail("POST", "/api/recyclebin/enable", map[string]any{}, "insufficient access")
	samDBUsable = func() bool { return true }
	c.fail("POST", "/api/recyclebin/enable", map[string]any{}, "only an Enterprise Admin")
	if calls != 0 || rb() != false {
		t.Fatal("fallback ran for a non-Enterprise-Admin or without the database")
	}
	ea := "CN=Enterprise Admins,CN=Users," + tBase
	d.mu.Lock()
	d.put(ea, "objectClass", "group", "name", "Enterprise Admins")
	d.put("CN=admin,CN=Users,"+tBase, "objectClass", "top", "objectClass", "person", "objectClass", "user", "sAMAccountName", "admin",
		"userPrincipalName", "admin@samdom.example.com", "memberOf", ea)
	d.mu.Unlock()
	ldbModifyLocal = func(string) error { return errors.New("boom") }
	c.fail("POST", "/api/recyclebin/enable", map[string]any{}, "local fallback failed")
	if rb() != false {
		t.Fatal("a failed fallback must change nothing")
	}
	ldbModifyLocal = okStub
	if r := c.ok("POST", "/api/recyclebin/enable", map[string]any{}); r["enabled"] != true || calls != 1 {
		t.Fatal(r, calls)
	}
	c.fail("POST", "/api/recyclebin/enable", map[string]any{}, "already enabled")
	d.mu.Lock()
	delete(d.dir[feat].attrs, "msDS-EnabledFeatureBL")
	d.mu.Unlock()
	d.mu.Lock()
	d.denyEnable = false
	d.mu.Unlock()
	if r := c.ok("POST", "/api/recyclebin/enable", map[string]any{}); r["enabled"] != true {
		t.Fatal(r)
	}
	if rb() != true {
		t.Fatal("not reported as enabled")
	}
	c.fail("POST", "/api/recyclebin/enable", map[string]any{}, "already enabled")
	// the Partitions record alone is also accepted as proof
	d.mu.Lock()
	delete(d.dir[feat].attrs, "msDS-EnabledFeatureBL")
	d.mu.Unlock()
	if rb() != true {
		t.Fatal("msDS-EnabledFeature on Partitions should count")
	}
}

// mockSysvol makes a scratch SYSVOL with the default GPO's folder.
func mockSysvol(t testing.TB) string {
	root, err := os.MkdirTemp("", "mock-sysvol")
	if err != nil {
		t.Fatal(err)
	}
	gdir := filepath.Join(root, "samdom.example.com", "Policies", tDefaultGPO)
	for _, sub := range []string{"Machine", "User"} {
		if err := os.MkdirAll(filepath.Join(gdir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(gdir, "GPT.INI"), []byte("[General]\r\nVersion=65537\r\n"), 0o644)
	return root
}

func TestDNSZoneCreate(t *testing.T) {
	c, d := setup(t)
	z := list(c.ok("GET", "/api/dns/zones", nil)["zones"])
	parent := z[0].(map[string]any)["dn"].(string)
	r := c.ok("POST", "/api/dns/zonecreate", map[string]any{"parent": parent, "name": "sub"})
	if r["name"] != "sub.samdom.example.com" {
		t.Fatalf("%v", r)
	}
	if d.dir[strings.ToLower("DC=@,"+r["dn"].(string))] == nil {
		t.Fatal("apex node missing")
	}
	recs := list(c.ok("GET", "/api/dns/records?zone="+r["dn"].(string), nil)["nodes"])
	if len(recs) != 1 || len(list(recs[0].(map[string]any)["records"])) != 2 {
		t.Fatalf("%v", recs)
	}
	if len(list(c.ok("GET", "/api/dns/zones", nil)["zones"])) != 2 {
		t.Fatal("zone not listed")
	}
	c.fail("POST", "/api/dns/zonecreate", map[string]any{"parent": parent, "name": "sub"}, "already exists")
	c.fail("POST", "/api/dns/zonecreate", map[string]any{"parent": parent, "name": "bad name"}, "not a valid zone name")
	c.fail("POST", "/api/dns/zonecreate", map[string]any{"parent": "CN=Users," + tBase, "name": "x"}, "not a DNS zone")
}
