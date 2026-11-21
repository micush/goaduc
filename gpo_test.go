package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolVectorAndRoundTrip(t *testing.T) {
	// key "A", value "B", DWORD 1 — laid out by hand from [MS-GPREG] 2.2
	want, _ := hex.DecodeString("50526567" + "01000000" + "5b00" + "410000" + "00" + "3b00" + "420000" + "00" + "3b00" + "04000000" + "3b00" + "04000000" + "3b00" + "01000000" + "5d00")
	got, err := buildPol([]PolEntry{{Key: "A", Value: "B", Type: regDWord, Data: "1"}})
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%x\n%x %v", got, want, err)
	}
	in := []PolEntry{
		{Key: `Software\Policies\Test`, Value: "Name", Type: regSZ, Data: "héllo wörld"},
		{Key: `Software\Policies\Test`, Value: "Path", Type: regExpandSZ, Data: `%SystemRoot%\x`},
		{Key: `Software\Policies\Test`, Value: "Big", Type: regQWord, Data: "18446744073709551615"},
		{Key: `Software\Policies\Test`, Value: "Dw", Type: regDWord, Data: "4294967295"},
		{Key: `Software\Policies\Test`, Value: "List", Type: regMultiSZ, Data: "one\ntwo\nthree"},
		{Key: `Software\Policies\Test`, Value: "Bin", Type: regBinary, Data: "00ff10"},
		{Key: `Software\Policies\Test`, Value: "**DeleteValues", Type: regSZ, Data: " "},
		{Key: `Software\Policies\Other`, Value: "", Type: 0, Data: ""},
	}
	b, err := buildPol(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := parsePol(b)
	if err != nil || fmt.Sprint(out) != fmt.Sprint(in[:6]) && false {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("%d entries back", len(out))
	}
	for i := range in {
		want := in[i]
		if want.Value == "**DeleteValues" {
			want.Data = strings.TrimRight(want.Data, "\x00")
		}
		if out[i] != want {
			t.Errorf("entry %d: %+v != %+v", i, out[i], want)
		}
	}
	if e, err := parsePol(nil); err != nil || len(e) != 0 {
		t.Fatal("empty file is an empty list")
	}
	for name, bad := range map[string][]byte{"header": []byte("junk----"), "trunc": want[:len(want)-1], "bracket": append(append([]byte{}, want[:8]...), 'x', 0)} {
		if _, err := parsePol(bad); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := buildPol([]PolEntry{{Key: "K", Value: "v", Type: regDWord, Data: "-1"}}); err == nil {
		t.Error("negative DWORD accepted")
	}
	if _, err := buildPol([]PolEntry{{Key: "", Value: "v", Type: regSZ}}); err == nil {
		t.Error("empty key accepted")
	}
	if _, err := buildPol([]PolEntry{{Key: "K", Value: "v", Type: regBinary, Data: "xyz"}}); err == nil {
		t.Error("bad hex accepted")
	}
}

func TestINIAndEncodings(t *testing.T) {
	secs := []iniSection{{Name: "System Access", Items: []iniItem{{Key: "MinimumPasswordLength", Value: "12"}, {Key: "PasswordComplexity", Value: "1"}}},
		{Name: "Privilege Rights", Items: []iniItem{{Key: "SeInteractiveLogonRight", Value: "*S-1-5-32-544,*S-1-5-32-545"}}}}
	txt, err := buildINI(secs)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(txt, "[Unicode]\r\nUnicode = yes\r\n") || !strings.Contains(txt, "[Version]\r\nsignature = \"$CHICAGO$\"") {
		t.Fatalf("Unicode/Version sections missing:\n%s", txt)
	}
	raw := encodeText(txt, "utf-16le")
	if raw[0] != 0xFF || raw[1] != 0xFE {
		t.Fatal("no UTF-16LE BOM")
	}
	back, enc := decodeText(raw)
	if enc != "utf-16le" || back != txt {
		t.Fatalf("%s %q", enc, back)
	}
	parsed := parseINI(back)
	if len(parsed) != 4 || parsed[1].Items[0].Key != "MinimumPasswordLength" || parsed[1].Items[0].Value != "12" || parsed[3].Items[0].Value != `"$CHICAGO$"` {
		t.Fatalf("%+v", parsed)
	}
	if _, err := buildINI([]iniSection{{Name: "bad]", Items: nil}}); err == nil {
		t.Error("bad section accepted")
	}
	if _, err := buildINI([]iniSection{{Name: "X", Items: []iniItem{{Key: "a=b", Value: "c"}}}}); err == nil {
		t.Error("key with = accepted")
	}
	if _, err := buildINI([]iniSection{{Name: "X", Items: []iniItem{{Key: "a", Value: "c\nd"}}}}); err == nil {
		t.Error("value with newline accepted")
	}
	for _, e := range []string{"utf-8", "utf-8-bom", "utf-16le", "utf-16be"} {
		if s, got := decodeText(encodeText("héllo\r\n", e)); s != "héllo\r\n" || got != e {
			t.Errorf("%s: %q %s", e, s, got)
		}
	}
	if _, _, ok := isTextFile([]byte{0, 1, 2, 0xff}); ok {
		t.Error("binary reported as text")
	}
}

func TestMergeExtAndGPLink(t *testing.T) {
	a := mergeExt("", cseRegistryMach.cse, cseRegistryMach.tool)
	if a != "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]" {
		t.Fatal(a)
	}
	b := mergeExt(a, cseSecurity.cse, cseSecurity.tool)
	if !strings.HasPrefix(b, "[{35378EAC") || !strings.HasSuffix(b, "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]") {
		t.Fatal(b)
	}
	if mergeExt(b, cseSecurity.cse, cseSecurity.tool) != b {
		t.Fatal("not idempotent")
	}
	if c := mergeExt(a, cseRegistryMach.cse, "{00000000-0000-0000-0000-000000000001}"); c != "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{00000000-0000-0000-0000-000000000001}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]" {
		t.Fatal(c)
	}
	v := "[LDAP://cn={AAAAAAAA-0000-0000-0000-000000000001},cn=policies,cn=system,DC=x;2][LDAP://cn={BBBBBBBB-0000-0000-0000-000000000002},cn=policies,cn=system,DC=x;1]"
	l := parseGPLink(v)
	if len(l) != 2 || l[0].Opt != 2 || l[1].Opt != 1 || l[1].guid() != "{BBBBBBBB-0000-0000-0000-000000000002}" || formatGPLink(l) != v {
		t.Fatalf("%+v", l)
	}
	if !extRe.MatchString("") || !extRe.MatchString(a) || extRe.MatchString("[x]") {
		t.Fatal("extRe")
	}
}

func TestSafeRelAndSymlinks(t *testing.T) {
	for _, bad := range []string{"../x", "a/../../x", "a/./b", "a\\..\\b", "x\x00y", "Machine/f.goaduc-tmp"} {
		if _, err := safeRel(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if p, err := safeRel(`/Machine\Scripts//Startup/`); err != nil || p != "Machine/Scripts/Startup" {
		t.Fatalf("%q %v", p, err)
	}
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "Machine"), 0o755)
	outside := t.TempDir()
	os.WriteFile(filepath.Join(outside, "secret"), []byte("x"), 0o644)
	os.Symlink(outside, filepath.Join(dir, "Machine", "link"))
	os.Symlink(filepath.Join(outside, "secret"), filepath.Join(dir, "Machine", "flink"))
	if _, _, err := gpoPath(dir, "Machine/link/secret"); err == nil {
		t.Error("followed a symlink out of the GPO folder")
	}
	if _, _, err := gpoPath(dir, "Machine/flink"); err == nil {
		t.Error("followed a file symlink")
	}
	// case-insensitive matching of existing components
	if p, ex, err := gpoPath(dir, "machine/New.txt"); err != nil || ex || p != filepath.Join(dir, "Machine", "New.txt") {
		t.Fatalf("%q %v %v", p, ex, err)
	}
}

// ---------- integration through the mock DC ----------

func gpoSetup(t *testing.T) (*tc, *mockDC, string) {
	c, d := setup(t)
	root := mockSysvol(t)
	t.Cleanup(func() { os.RemoveAll(root) })
	gdir := filepath.Join(root, "samdom.example.com", "Policies", tDefaultGPO)
	old := sysvolRoot
	sysvolRoot = root
	t.Cleanup(func() { sysvolRoot = old })
	return c, d, gdir
}

func gpoByName(c *tc, name string) map[string]any {
	for _, g := range list(c.ok("GET", "/api/gpo/list", nil)["gpos"]) {
		if g.(map[string]any)["name"] == name {
			return g.(map[string]any)
		}
	}
	c.t.Fatalf("no GPO %q", name)
	return nil
}

func TestGPOList(t *testing.T) {
	c, _, _ := gpoSetup(t)
	r := c.ok("GET", "/api/gpo/list", nil)
	sv := r["sysvol"].(map[string]any)
	if sv["available"] != true || sv["writable"] != true {
		t.Fatalf("%v", sv)
	}
	g := gpoByName(c, "Default Domain Policy")
	if g["guid"] != tDefaultGPO || g["userVersion"] != 1.0 || g["machineVersion"] != 1.0 || g["gptVersion"] != 65537.0 || g["created"] != "2026-01-01 12:00:00" {
		t.Fatalf("%v", g)
	}
	ls := list(g["links"])
	if len(ls) != 1 || ls[0].(map[string]any)["target"] != tBase || ls[0].(map[string]any)["order"] != 1.0 || ls[0].(map[string]any)["kind"] != "domain" {
		t.Fatalf("%v", ls)
	}
}

func TestGPOLifecycleAndLinks(t *testing.T) {
	c, _, gdir := gpoSetup(t)
	staff := "OU=Staff," + tBase
	pol := filepath.Dir(gdir)

	c.fail("POST", "/api/gpo/create", map[string]any{"name": ""}, "name is required")
	c.fail("POST", "/api/gpo/create", map[string]any{"name": "Default Domain Policy"}, "already exists")
	r := c.ok("POST", "/api/gpo/create", map[string]any{"name": "Workstations", "linkTo": staff})
	a := r["guid"].(string)
	if !guidRe.MatchString(a) {
		t.Fatal(a)
	}
	for _, p := range []string{"GPT.INI", "Machine", "User"} {
		if _, err := os.Stat(filepath.Join(pol, a, p)); err != nil {
			t.Fatalf("SYSVOL %s: %v", p, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(pol, a, "GPT.INI")); !strings.Contains(string(b), "Version=0") {
		t.Fatalf("%s", b)
	}
	g := gpoByName(c, "Workstations")
	if g["flags"] != 0.0 || !strings.Contains(g["path"].(string), a) || len(list(g["links"])) != 1 {
		t.Fatalf("%v", g)
	}
	// second GPO linked to the same OU: new links start at the lowest precedence
	b := c.ok("POST", "/api/gpo/create", map[string]any{"name": "Servers", "linkTo": staff})["guid"].(string)
	order := func(name string) float64 {
		return list(gpoByName(c, name)["links"])[0].(map[string]any)["order"].(float64)
	}
	if order("Workstations") != 1 || order("Servers") != 2 {
		t.Fatalf("orders %v %v", order("Workstations"), order("Servers"))
	}
	c.ok("POST", "/api/gpo/move", map[string]any{"guid": b, "target": staff, "delta": -1})
	if order("Servers") != 1 || order("Workstations") != 2 {
		t.Fatalf("after move: %v %v", order("Servers"), order("Workstations"))
	}
	c.ok("POST", "/api/gpo/move", map[string]any{"guid": b, "target": staff, "delta": -1}) // already first: no-op
	if order("Servers") != 1 {
		t.Fatal("moved past the top")
	}
	c.fail("POST", "/api/gpo/move", map[string]any{"guid": b, "target": staff, "delta": 2}, "delta")
	// options, inheritance
	c.ok("POST", "/api/gpo/link", map[string]any{"guid": b, "target": staff, "enforced": true, "disabled": true})
	l := list(gpoByName(c, "Servers")["links"])[0].(map[string]any)
	if l["enforced"] != true || l["disabled"] != true {
		t.Fatalf("%v", l)
	}
	if len(list(gpoByName(c, "Servers")["links"])) != 1 {
		t.Fatal("re-linking must update, not duplicate")
	}
	c.ok("POST", "/api/gpo/inherit", map[string]any{"target": staff, "block": true})
	if list(gpoByName(c, "Servers")["links"])[0].(map[string]any)["block"] != true {
		t.Fatal("block inheritance not shown")
	}
	c.ok("POST", "/api/gpo/inherit", map[string]any{"target": staff, "block": false})
	// bad targets and ids
	c.fail("POST", "/api/gpo/link", map[string]any{"guid": b, "target": "CN=Users," + tBase}, "domain, an OU or a site")
	c.fail("POST", "/api/gpo/link", map[string]any{"guid": "{00000000-0000-0000-0000-000000000000}", "target": staff}, "GPO")
	c.fail("POST", "/api/gpo/link", map[string]any{"guid": "nope", "target": staff}, "invalid GPO")
	// status, rename, extension lists
	c.ok("POST", "/api/gpo/status", map[string]any{"guid": b, "flags": 3})
	c.fail("POST", "/api/gpo/status", map[string]any{"guid": b, "flags": 4}, "0 to 3")
	c.ok("POST", "/api/gpo/rename", map[string]any{"guid": b, "name": "Server Baseline"})
	c.fail("POST", "/api/gpo/rename", map[string]any{"guid": b, "name": "Workstations"}, "already exists")
	g = gpoByName(c, "Server Baseline")
	if g["flags"] != 3.0 {
		t.Fatalf("%v", g)
	}
	ext := "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
	c.ok("POST", "/api/gpo/ext", map[string]any{"guid": b, "machine": ext, "user": ""})
	if gpoByName(c, "Server Baseline")["machineExt"] != ext {
		t.Fatal("extension list not stored")
	}
	c.fail("POST", "/api/gpo/ext", map[string]any{"guid": b, "machine": "junk", "user": ""}, "extension lists")
	// unlink
	c.ok("POST", "/api/gpo/unlink", map[string]any{"guid": b, "target": staff})
	if len(list(gpoByName(c, "Server Baseline")["links"])) != 0 {
		t.Fatal("still linked")
	}
	// delete: removes remaining links and the SYSVOL folder; built-ins are refused
	c.fail("POST", "/api/gpo/delete", map[string]any{"guid": tDefaultGPO}, "cannot be deleted")
	r = c.ok("POST", "/api/gpo/delete", map[string]any{"guid": a})
	if r["unlinked"] != 1.0 {
		t.Fatalf("%v", r)
	}
	if _, err := os.Stat(filepath.Join(pol, a)); !os.IsNotExist(err) {
		t.Fatal("SYSVOL folder left behind")
	}
	for _, g := range list(c.ok("GET", "/api/gpo/list", nil)["gpos"]) {
		if g.(map[string]any)["guid"] == a {
			t.Fatal("still listed")
		}
	}
	c.fail("POST", "/api/gpo/delete", map[string]any{"guid": a}, "")
}

func TestGPORegistryAndSecurity(t *testing.T) {
	c, _, gdir := gpoSetup(t)
	q := "/api/gpo/registry?guid=" + tDefaultGPO + "&scope="
	r := c.ok("GET", q+"machine", nil)
	if len(list(r["entries"])) != 0 || r["exists"] != false || r["etag"] != "" {
		t.Fatalf("%v", r)
	}
	e1 := []map[string]any{{"key": `Software\Policies\Test`, "value": "Enabled", "type": 4, "data": "1"}, {"key": `Software\Policies\Test`, "value": "Name", "type": 1, "data": "x y"}}
	c.fail("POST", "/api/gpo/registry/save", map[string]any{"guid": tDefaultGPO, "scope": "machine", "etag": "", "entries": []map[string]any{{"key": "K", "value": "v", "type": 4, "data": "abc"}}}, "DWORD")
	if g := gpoByName(c, "Default Domain Policy"); g["machineVersion"] != 1.0 {
		t.Fatal("a rejected save must not bump the version")
	}
	r = c.ok("POST", "/api/gpo/registry/save", map[string]any{"guid": tDefaultGPO, "scope": "machine", "etag": "", "entries": e1})
	etag := r["etag"].(string)
	b, err := os.ReadFile(filepath.Join(gdir, "Machine", "Registry.pol"))
	if err != nil {
		t.Fatal(err)
	}
	if es, err := parsePol(b); err != nil || len(es) != 2 || es[0].Data != "1" || es[1].Data != "x y" {
		t.Fatalf("%v %v", es, err)
	}
	g := gpoByName(c, "Default Domain Policy")
	if g["machineVersion"] != 2.0 || g["userVersion"] != 1.0 || g["gptVersion"] != 65538.0 || g["machineExt"] != "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]" {
		t.Fatalf("%v", g)
	}
	if v, _ := readGPTVersion(gdir); v != 65538 {
		t.Fatalf("GPT.INI says %d", v)
	}
	// stale etag: refused, and it must not burn a version number
	c.fail("POST", "/api/gpo/registry/save", map[string]any{"guid": tDefaultGPO, "scope": "machine", "etag": "stale", "entries": e1}, "changed by someone else")
	if g := gpoByName(c, "Default Domain Policy"); g["machineVersion"] != 2.0 {
		t.Fatalf("a refused save bumped the version: %v", g["machineVersion"])
	}
	// reload and edit, then the user half
	r = c.ok("GET", q+"machine", nil)
	if r["etag"] != etag || len(list(r["entries"])) != 2 {
		t.Fatalf("%v", r)
	}
	c.ok("POST", "/api/gpo/registry/save", map[string]any{"guid": tDefaultGPO, "scope": "user", "etag": "", "entries": e1[:1]})
	g = gpoByName(c, "Default Domain Policy")
	if g["userVersion"] != 2.0 || g["machineVersion"] != 2.0 || !strings.Contains(g["userExt"].(string), "D02B1F73") {
		t.Fatalf("%v", g)
	}
	c.fail("GET", q+"nowhere", nil, "scope")

	// security settings
	sq := "/api/gpo/security?guid=" + tDefaultGPO
	r = c.ok("GET", sq, nil)
	if r["exists"] != false {
		t.Fatal(r)
	}
	secs := []map[string]any{{"name": "System Access", "items": []map[string]any{{"key": "MinimumPasswordLength", "value": "14"}}}}
	c.ok("POST", "/api/gpo/security/save", map[string]any{"guid": tDefaultGPO, "etag": "", "sections": secs})
	raw, err := os.ReadFile(filepath.Join(gdir, "Machine", "Microsoft", "Windows NT", "SecEdit", "GptTmpl.inf"))
	if err != nil || raw[0] != 0xFF || raw[1] != 0xFE {
		t.Fatalf("%v %x", err, raw[:2])
	}
	r = c.ok("GET", sq, nil)
	ss := list(r["sections"])
	if len(ss) != 3 || ss[1].(map[string]any)["name"] != "System Access" {
		t.Fatalf("%v", ss)
	}
	g = gpoByName(c, "Default Domain Policy")
	if g["machineVersion"] != 3.0 || !strings.Contains(g["machineExt"].(string), "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}") {
		t.Fatalf("%v", g)
	}
	c.fail("POST", "/api/gpo/security/save", map[string]any{"guid": tDefaultGPO, "etag": "old", "sections": secs}, "changed by someone else")
	if g := gpoByName(c, "Default Domain Policy"); g["machineVersion"] != 3.0 {
		t.Fatalf("a refused save bumped the version: %v", g["machineVersion"])
	}
}

func TestGPOFiles(t *testing.T) {
	c, _, gdir := gpoSetup(t)
	post := func(p string, b map[string]any) map[string]any { b["guid"] = tDefaultGPO; return c.ok("POST", p, b) }
	fail := func(p string, b map[string]any, want string) { b["guid"] = tDefaultGPO; c.fail("POST", p, b, want) }
	q := "?guid=" + tDefaultGPO

	post("/api/gpo/file/mkdir", map[string]any{"path": "Machine/Scripts/Startup"})
	if st, err := os.Stat(filepath.Join(gdir, "Machine", "Scripts", "Startup")); err != nil || !st.IsDir() {
		t.Fatal("folder not made")
	}
	fail("/api/gpo/file/mkdir", map[string]any{"path": "Machine/Scripts"}, "already exists")
	r := post("/api/gpo/file/save", map[string]any{"path": "Machine/Scripts/Startup/hello.cmd", "create": true, "encoding": "utf-8", "text": "@echo off\r\necho hi\r\n"})
	etag := r["etag"].(string)
	f := c.ok("GET", "/api/gpo/file"+q+"&path=Machine/Scripts/Startup/hello.cmd", nil)
	if f["kind"] != "text" || f["text"] != "@echo off\r\necho hi\r\n" || f["etag"] != etag || f["encoding"] != "utf-8" {
		t.Fatalf("%v", f)
	}
	fail("/api/gpo/file/save", map[string]any{"path": "Machine/Scripts/Startup/hello.cmd", "create": true, "text": "x"}, "already exists")
	fail("/api/gpo/file/save", map[string]any{"path": "Machine/Scripts/Startup/hello.cmd", "etag": "stale", "text": "x"}, "changed by someone else")
	post("/api/gpo/file/save", map[string]any{"path": "machine/scripts/startup/hello.cmd", "etag": etag, "encoding": "utf-16le", "text": "new"})
	f = c.ok("GET", "/api/gpo/file"+q+"&path=Machine/Scripts/Startup/hello.cmd", nil)
	if f["encoding"] != "utf-16le" || f["text"] != "new" {
		t.Fatalf("%v", f)
	}
	// uploads of binary data
	bin := []byte{0, 1, 2, 0xff, 0xfe}
	fail("/api/gpo/file/save", map[string]any{"path": "User/Scripts/Logon/y.bin", "create": true, "b64": base64.StdEncoding.EncodeToString(bin)}, "does not exist")
	post("/api/gpo/file/mkdir", map[string]any{"path": "User/Scripts/Logon"})
	post("/api/gpo/file/save", map[string]any{"path": "User/Scripts/Logon/x.bin", "create": true, "b64": base64.StdEncoding.EncodeToString(bin)})
	f = c.ok("GET", "/api/gpo/file"+q+"&path=User/Scripts/Logon/x.bin", nil)
	if f["kind"] != "binary" || f["b64"] != base64.StdEncoding.EncodeToString(bin) {
		t.Fatalf("%v", f)
	}
	// listing
	l := list(c.ok("GET", "/api/gpo/files"+q+"&path=", nil)["files"])
	if names(l, "name") != "Machine,User,GPT.INI" {
		t.Fatalf("%s", names(l, "name"))
	}
	if n := names(c.ok("GET", "/api/gpo/files"+q+"&path=Machine/Scripts/Startup", nil)["files"], "name"); n != "hello.cmd" {
		t.Fatal(n)
	}
	// each change bumped the matching half
	g := gpoByName(c, "Default Domain Policy")
	if g["machineVersion"].(float64) < 4 || g["userVersion"].(float64) < 3 {
		t.Fatalf("%v", g)
	}
	// refusals
	for _, p := range []string{"../escape", "Machine/../GPT.INI", "GPT.INI", "Other/x", "", "/", "Machine/a\x00b"} {
		fail("/api/gpo/file/save", map[string]any{"path": p, "create": true, "text": "x"}, "")
	}
	fail("/api/gpo/file/delete", map[string]any{"path": "Machine"}, "can't be deleted")
	fail("/api/gpo/file/delete", map[string]any{"path": "GPT.INI"}, "Machine and User")
	fail("/api/gpo/file/delete", map[string]any{"path": "Machine/nothing"}, "no such")
	c.fail("GET", "/api/gpo/file"+q+"&path=../../../etc/passwd", nil, "invalid path")
	c.fail("GET", "/api/gpo/files"+q+"&path=Machine/..", nil, "invalid path")
	post("/api/gpo/file/delete", map[string]any{"path": "Machine/Scripts"})
	if _, err := os.Stat(filepath.Join(gdir, "Machine", "Scripts")); !os.IsNotExist(err) {
		t.Fatal("folder not deleted")
	}
	// GET of an unknown GPO
	c.fail("GET", "/api/gpo/files?guid={00000000-0000-0000-0000-000000000000}&path=", nil, "")
}

func TestGPOWriteNeedsLDAPRight(t *testing.T) {
	c, d, gdir := gpoSetup(t)
	d.mu.Lock()
	d.denyGPOWrite = true
	d.mu.Unlock()
	body := map[string]any{"guid": tDefaultGPO, "scope": "machine", "etag": "", "entries": []map[string]any{{"key": "K", "value": "v", "type": 1, "data": "x"}}}
	c.fail("POST", "/api/gpo/registry/save", body, "insufficient access")
	c.fail("POST", "/api/gpo/file/save", map[string]any{"guid": tDefaultGPO, "path": "Machine/a.txt", "create": true, "text": "x"}, "insufficient access")
	c.fail("POST", "/api/gpo/file/mkdir", map[string]any{"guid": tDefaultGPO, "path": "Machine/d"}, "insufficient access")
	if es, _ := os.ReadDir(filepath.Join(gdir, "Machine")); len(es) != 0 {
		t.Fatalf("files written without the LDAP right: %v", es)
	}
}

func TestGPONoSysvol(t *testing.T) {
	c, _ := setup(t)
	old := sysvolRoot
	sysvolRoot = ""
	defer func() { sysvolRoot = old }()
	r := c.ok("GET", "/api/gpo/list", nil)
	if r["sysvol"].(map[string]any)["available"] != false || len(list(r["gpos"])) != 1 {
		t.Fatalf("%v", r)
	}
	c.fail("POST", "/api/gpo/create", map[string]any{"name": "X"}, "SYSVOL is not available")
	c.fail("GET", "/api/gpo/registry?guid="+tDefaultGPO+"&scope=machine", nil, "SYSVOL is not available")
}
