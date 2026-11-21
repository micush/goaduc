package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type tent struct {
	name, body string
	typ        byte
	link       string
}

func mkTgz(t *testing.T, ents []tent) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range ents {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o644, Size: int64(len(e.body)), Linkname: e.link}
		if typ == tar.TypeDir || typ == tar.TypeSymlink {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

// a tiny but real goaduc-shaped module: go build runs on it, and it answers --version like the real one
func releaseTgz(t *testing.T, ver string) []byte {
	return mkTgz(t, []tent{
		{name: "goaduc/", typ: tar.TypeDir},
		{name: "goaduc/go.mod", body: "module goaduc\n\ngo 1.21\n"},
		{name: "goaduc/main.go", body: "package main\n\nimport (\n\t_ \"embed\"\n\t\"fmt\"\n\t\"os\"\n\t\"strings\"\n)\n\n//go:embed VERSION\nvar v string\n\nfunc main() {\n\tif len(os.Args) > 1 && os.Args[1] == \"--version\" {\n\t\tfmt.Println(\"goaduc v\" + strings.TrimSpace(v))\n\t}\n}\n"},
		{name: "goaduc/VERSION", body: ver + "\n"},
		{name: "goaduc/static/index.html", body: "<!doctype html>"},
	})
}

func writeTemp(t *testing.T, dir, name string, b []byte) string {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// updateEnv points the updater at a scratch directory and a fake installed binary, and records re-execs.
func updateEnv(t *testing.T) (exe string, execs *int32) {
	t.Helper()
	dir := t.TempDir()
	updateDir = filepath.Join(dir, "state")
	exe = filepath.Join(dir, "goaduc")
	if err := os.WriteFile(exe, []byte("OLD"), 0o755); err != nil {
		t.Fatal(err)
	}
	execs = new(int32)
	oe, ox, or, ob, of := updateExe, updateExec, updateRestartIn, updateBuild, updateFindGo
	od, ot := updateDisabled, bootConfirmAfter
	updateExe = func() (string, error) { return exe, nil }
	updateExec = func(string) error { atomic.AddInt32(execs, 1); return nil }
	updateRestartIn = 0
	updateJob = updateJobState{}
	t.Cleanup(func() {
		updateExe, updateExec, updateRestartIn, updateBuild, updateFindGo = oe, ox, or, ob, of
		updateDisabled, bootConfirmAfter = od, ot
		updateJob = updateJobState{}
	})
	return exe, execs
}

func TestExtractUpdateSafety(t *testing.T) {
	bad := map[string][]tent{
		"dotdot":    {{name: "goaduc/../../evil", body: "x"}},
		"absolute":  {{name: "/etc/passwd", body: "x"}},
		"symlink":   {{name: "goaduc/link", typ: tar.TypeSymlink, link: "/etc"}},
		"hardlink":  {{name: "goaduc/hl", typ: tar.TypeLink, link: "goaduc/go.mod"}},
		"device":    {{name: "goaduc/dev", typ: tar.TypeChar}},
		"backslash": {{name: "goaduc\\evil", body: "x"}},
	}
	for name, ents := range bad {
		src := writeTemp(t, t.TempDir(), "a.tgz", mkTgz(t, ents))
		dst := filepath.Join(t.TempDir(), "tree")
		if _, err := extractUpdate(src, dst); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// nothing escaped
	if _, err := os.Stat("/evil"); err == nil {
		t.Fatal("wrote outside the tree")
	}
	// not a gzip file
	if _, err := extractUpdate(writeTemp(t, t.TempDir(), "x.tgz", []byte("hello")), filepath.Join(t.TempDir(), "t")); err == nil {
		t.Error("accepted a non-archive")
	}
	// no go.mod anywhere
	src := writeTemp(t, t.TempDir(), "a.tgz", mkTgz(t, []tent{{name: "goaduc/readme", body: "x"}}))
	if _, err := extractUpdate(src, filepath.Join(t.TempDir(), "t")); err == nil || !strings.Contains(err.Error(), "go.mod") {
		t.Errorf("no go.mod: %v", err)
	}
	// good, in a top-level directory (our archive and GitHub's) and flat
	for _, top := range []string{"goaduc/", "goaduc-v99/", ""} {
		src := writeTemp(t, t.TempDir(), "a.tgz", mkTgz(t, []tent{{name: top + "go.mod", body: "module x\n"}, {name: top + "VERSION", body: "99"}}))
		dst := filepath.Join(t.TempDir(), "tree")
		root, err := extractUpdate(src, dst)
		if err != nil {
			t.Fatalf("%q: %v", top, err)
		}
		if _, err := os.Stat(filepath.Join(root, "VERSION")); err != nil {
			t.Errorf("%q: root %s has no VERSION", top, root)
		}
	}
}

func TestCheckTree(t *testing.T) {
	mk := func(ver string, skip string) string {
		d := t.TempDir()
		for f, b := range map[string]string{"go.mod": "module x", "main.go": "package main", "VERSION": ver, "static/index.html": "x"} {
			if f == skip {
				continue
			}
			os.MkdirAll(filepath.Dir(filepath.Join(d, f)), 0o755)
			os.WriteFile(filepath.Join(d, f), []byte(b), 0o644)
		}
		return d
	}
	cur := curVersion()
	if n, err := checkTree(mk(strconv.Itoa(cur+1)+"\n", "")); err != nil || n != cur+1 {
		t.Fatalf("newer: %d %v", n, err)
	}
	for name, tree := range map[string]string{
		"same":      mk(strconv.Itoa(cur), ""),
		"older":     mk(strconv.Itoa(cur-1), ""),
		"semver":    mk("1.2.3", ""),
		"padded":    mk("0"+strconv.Itoa(cur+1), ""),
		"empty":     mk("", ""),
		"no main":   mk(strconv.Itoa(cur+1), "main.go"),
		"no static": mk(strconv.Itoa(cur+1), "static/index.html"),
	} {
		if _, err := checkTree(tree); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func goOrSkip(t *testing.T) {
	if updateFindGo() == "" {
		t.Skip("no Go toolchain")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not on PATH")
	}
}

func TestUpdatePipeline(t *testing.T) {
	goOrSkip(t)
	exe, execs := updateEnv(t)
	to := curVersion() + 1
	arc := writeTemp(t, t.TempDir(), "r.tgz", releaseTgz(t, strconv.Itoa(to)))
	fetch := func(dst string) error { return copyFile(arc, dst, 0o600) }
	if err := doUpdate("tester", fetch); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(exe, "--version").Output()
	if err != nil || strings.TrimSpace(string(out)) != "goaduc v"+strconv.Itoa(to) {
		t.Fatalf("installed binary: %q %v", out, err)
	}
	if b, _ := os.ReadFile(exe + ".prev"); string(b) != "OLD" {
		t.Fatalf("previous binary not kept: %q", b)
	}
	st, ok := readUpdateState()
	if !ok || st.State != "applying" || st.To != to || st.From != curVersion() || st.By != "tester" || st.Prev != exe+".prev" {
		t.Fatalf("%+v", st)
	}
	if atomic.LoadInt32(execs) != 1 {
		t.Fatal("did not restart")
	}
	if m, _ := filepath.Glob(filepath.Join(updateDir, "work-*")); len(m) != 0 {
		t.Fatalf("work directory left behind: %v", m)
	}
}

func TestUpdateRefusalsChangeNothing(t *testing.T) {
	exe, execs := updateEnv(t)
	to := curVersion() + 1
	arc := writeTemp(t, t.TempDir(), "r.tgz", releaseTgz(t, strconv.Itoa(to)))
	fetch := func(dst string) error { return copyFile(arc, dst, 0o600) }
	same := writeTemp(t, t.TempDir(), "s.tgz", releaseTgz(t, strconv.Itoa(curVersion())))
	untouched := func(why string, err error, want string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: %v", why, err)
		}
		if b, _ := os.ReadFile(exe); string(b) != "OLD" {
			t.Fatalf("%s: binary changed", why)
		}
		if _, ok := readUpdateState(); ok {
			t.Fatalf("%s: state written", why)
		}
		if atomic.LoadInt32(execs) != 0 {
			t.Fatalf("%s: restarted", why)
		}
	}
	untouched("same version", doUpdate("t", func(dst string) error { return copyFile(same, dst, 0o600) }), "already installed")
	updateFindGo = func() string { return "" }
	untouched("no go", doUpdate("t", fetch), "no Go toolchain")
	updateFindGo = func() string { return "/bin/true" }
	updateBuild = func(goBin, tree, work, out string) error { return os.ErrPermission }
	untouched("build fails", doUpdate("t", fetch), "permission")
	updateBuild = func(goBin, tree, work, out string) error {
		return os.WriteFile(out, []byte("#!/bin/sh\necho goaduc v1\n"), 0o755)
	}
	untouched("wrong version built", doUpdate("t", fetch), "expected goaduc v"+strconv.Itoa(to))
	untouched("download fails", doUpdate("t", func(string) error { return os.ErrNotExist }), "not exist")
}

func TestBootGuard(t *testing.T) {
	exe, execs := updateEnv(t)
	prev := exe + ".prev"
	os.WriteFile(exe, []byte("NEW"), 0o755)
	os.WriteFile(prev, []byte("OLD"), 0o755)
	cur := curVersion()
	// not the version the state is waiting for: a rollback happened already or someone reinstalled
	writeUpdateState(updateState{State: "applying", From: cur - 1, To: cur + 5, Prev: prev})
	updateBoot()
	if st, _ := readUpdateState(); st.State != "rolled-back" {
		t.Fatalf("%+v", st)
	}
	if b, _ := os.ReadFile(exe); string(b) != "NEW" || *execs != 0 {
		t.Fatal("touched the binary for another version")
	}
	// the new version starting again and again is replaced after maxBootAttempts
	writeUpdateState(updateState{State: "applying", From: cur - 1, To: cur, Prev: prev})
	bootConfirmAfter = time.Hour
	for i := 1; i <= maxBootAttempts; i++ {
		updateBoot()
		if st, _ := readUpdateState(); st.State != "applying" || st.Attempts != i {
			t.Fatalf("attempt %d: %+v", i, st)
		}
	}
	if b, _ := os.ReadFile(exe); string(b) != "NEW" || *execs != 0 {
		t.Fatal("rolled back too early")
	}
	updateBoot()
	if b, _ := os.ReadFile(exe); string(b) != "OLD" {
		t.Fatalf("not restored: %q", b)
	}
	if st, _ := readUpdateState(); st.State != "rolled-back" || st.Err == "" {
		t.Fatalf("%+v", st)
	}
	if *execs != 1 {
		t.Fatal("did not restart into the old binary")
	}
	// no saved binary: say so, do not pretend
	writeUpdateState(updateState{State: "applying", From: cur - 1, To: cur, Attempts: maxBootAttempts, Prev: filepath.Join(t.TempDir(), "gone")})
	updateBoot()
	if st, _ := readUpdateState(); st.State != "failed" || !strings.Contains(st.Err, "restoring") {
		t.Fatalf("%+v", st)
	}
	// a start that stays up is accepted
	writeUpdateState(updateState{State: "applying", From: cur - 1, To: cur, Prev: prev})
	bootConfirmAfter = 20 * time.Millisecond
	updateBoot()
	time.Sleep(300 * time.Millisecond)
	if st, _ := readUpdateState(); st.State != "ok" || st.Attempts != 0 {
		t.Fatalf("%+v", st)
	}
}

func TestLatestTag(t *testing.T) {
	var releases bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/releases/latest":
			if !releases {
				http.NotFound(w, r)
				return
			}
			w.Write([]byte(`{"tag_name":"v77"}`))
		case "/repos/o/r/tags":
			w.Write([]byte(`[{"name":"v9"},{"name":"v100"},{"name":"nightly"},{"name":"v12"},{"name":"../x"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oa, or := updateAPI, updateRepo
	updateAPI, updateRepo = srv.URL, "o/r"
	defer func() { updateAPI, updateRepo = oa, or }()
	releases = true
	if tag, err := latestTag(); err != nil || tag != "v77" {
		t.Fatalf("release: %q %v", tag, err)
	}
	releases = false
	if tag, err := latestTag(); err != nil || tag != "v100" {
		t.Fatalf("tags: %q %v", tag, err)
	}
	if tagVersion("v100") != 100 || tagVersion("12") != 12 || tagVersion("nightly") != 0 {
		t.Fatal("tagVersion")
	}
}

func TestUpdateAPI(t *testing.T) {
	goOrSkip(t)
	exe, execs := updateEnv(t)
	c, d := setup(t)
	to := curVersion() + 1
	release := releaseTgz(t, strconv.Itoa(to))
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/repos/o/r/releases/latest"):
			w.Write([]byte(`{"tag_name":"v` + strconv.Itoa(to) + `"}`))
		case strings.HasSuffix(r.URL.Path, "/archive/refs/tags/v"+strconv.Itoa(to)+".tar.gz"):
			w.Write(release)
		default:
			http.NotFound(w, r)
		}
	}))
	defer gh.Close()
	oa, oh, or := updateAPI, updateHost, updateRepo
	updateAPI, updateHost, updateRepo = gh.URL, gh.URL, "o/r"
	defer func() { updateAPI, updateHost, updateRepo = oa, oh, or }()

	status := func() map[string]any { return c.ok("GET", "/api/update", nil) }
	// a signed-in user who is not a Domain Admin or Enterprise Admin
	if s := status(); s["admin"] != false || s["canApply"] != false || s["version"] != float64(curVersion()) {
		t.Fatalf("%v", s)
	}
	raw := func(body []byte) (int, string) {
		req, _ := http.NewRequest("POST", c.srv.URL+"/api/update/upload", bytes.NewReader(body))
		req.Header.Set("X-Requested-With", "aduc")
		resp, err := c.cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		e, _ := m["error"].(string)
		return resp.StatusCode, e
	}
	c.fail("POST", "/api/update/check", map[string]any{}, "only Domain Admins")
	c.fail("POST", "/api/update/online", map[string]any{}, "only Domain Admins")
	if code, e := raw(release); code == 200 || !strings.Contains(e, "only Domain Admins") {
		t.Fatalf("upload by a non-admin: %d %q", code, e)
	}
	if b, _ := os.ReadFile(exe); string(b) != "OLD" || *execs != 0 {
		t.Fatal("a non-admin changed the binary")
	}
	// make the signed-in user a Domain Admin (the in-chain match is what the mock evaluates)
	da := "CN=Domain Admins,CN=Users," + tBase
	d.mu.Lock()
	d.put("CN=admin,CN=Users,"+tBase, "objectClass", "top", "objectClass", "person", "objectClass", "user", "sAMAccountName", "admin",
		"userPrincipalName", "admin@samdom.example.com", "memberOf", da)
	d.mu.Unlock()
	if s := status(); s["admin"] != true || s["canApply"] != true {
		t.Fatalf("%v", s)
	}
	if r := c.ok("POST", "/api/update/check", map[string]any{}); r["tag"] != "v"+strconv.Itoa(to) || r["newer"] != true {
		t.Fatalf("%v", r)
	}
	// turned off with -no-update, even for an admin
	updateDisabled = true
	c.fail("POST", "/api/update/check", map[string]any{}, "turned off")
	if s := status(); s["enabled"] != false || s["canApply"] != false {
		t.Fatalf("%v", s)
	}
	updateDisabled = false
	// bad tag
	c.fail("POST", "/api/update/online", map[string]any{"tag": "../etc"}, "bad tag")

	wait := func() map[string]any {
		var s map[string]any
		for i := 0; i < 400; i++ {
			s = status()
			if atomic.LoadInt32(execs) > 0 || (s["job"].(map[string]any)["state"] == "failed") {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		return s
	}
	// online
	c.ok("POST", "/api/update/online", map[string]any{})
	s := wait()
	if atomic.LoadInt32(execs) != 1 {
		t.Fatalf("online update did not finish: %v", s)
	}
	if out, _ := exec.Command(exe, "--version").Output(); strings.TrimSpace(string(out)) != "goaduc v"+strconv.Itoa(to) {
		t.Fatalf("%q", out)
	}
	if last := s["last"].(map[string]any); last["state"] != "applying" || last["by"] != "admin@samdom.example.com" {
		t.Fatalf("%v", last)
	}
	// upload: the same version is refused by the pipeline (it is only a job, so look at the job)
	os.WriteFile(exe, []byte("OLD"), 0o755)
	atomic.StoreInt32(execs, 0)
	updateJob = updateJobState{}
	if code, e := raw(releaseTgz(t, strconv.Itoa(curVersion()))); code != 200 {
		t.Fatalf("upload: %d %s", code, e)
	}
	s = wait()
	if j := s["job"].(map[string]any); j["state"] != "failed" || !strings.Contains(j["msg"].(string), "already installed") {
		t.Fatalf("%v", j)
	}
	if b, _ := os.ReadFile(exe); string(b) != "OLD" {
		t.Fatal("refused upload changed the binary")
	}
	// upload of a newer one
	updateJob = updateJobState{}
	if code, e := raw(release); code != 200 {
		t.Fatalf("upload: %d %s", code, e)
	}
	wait()
	if atomic.LoadInt32(execs) != 1 {
		t.Fatalf("upload did not finish: %v", status()["job"])
	}
	// garbage and empty uploads
	updateJob = updateJobState{}
	if code, _ := raw(nil); code == 200 {
		t.Fatal("empty upload accepted")
	}
	if m, _ := filepath.Glob(filepath.Join(updateDir, "upload-*")); len(m) != 0 {
		t.Fatalf("upload files left behind: %v", m)
	}
}
