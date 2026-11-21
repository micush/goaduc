package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// In-app software update (the Update page). A release is either fetched from GitHub or uploaded as the goaduc_vN.tgz
// this project ships; it is unpacked, built here with the Go toolchain the installer keeps (CGO off, so the binary is
// static), checked with --version, swapped in for the running binary and started with a re-exec (same PID, so systemd
// notices nothing). The old binary is kept (the installer's goaduc.prev) and a boot guard puts it back if the new one
// keeps failing to start.
//
// Only a Domain Admin or an Enterprise Admin (checked over the signed-in user's own LDAP connection) may update: the
// service usually runs as root, so this is code execution as root and has to be as restricted as the account that owns
// the domain. -no-update turns it off.

const (
	defaultUpdateRepo  = "micush/goaduc"
	maxUpdateArchive   = 32 << 20
	maxUpdateFiles     = 2000
	maxUpdateFile      = 16 << 20
	maxUpdateTotal     = 64 << 20
	updateBuildTimeout = 10 * time.Minute
	maxBootAttempts    = 3
)

var (
	updateRepo       = defaultUpdateRepo
	updateDisabled   bool
	updateAPI        = "https://api.github.com" // test hooks
	updateHost       = "https://github.com"
	updateDir        string                    // <data dir>/update: work trees, uploads and state.json
	bootConfirmAfter = 60 * time.Second        // the new binary is "ok" once it has been up this long
	updateRestartIn  = 1500 * time.Millisecond // let the HTTP reply and the audit entry out before the re-exec

	updateExe = func() (string, error) {
		p, err := os.Executable()
		if err != nil {
			return "", err
		}
		return filepath.EvalSymlinks(p)
	}
	updateExec   = func(exe string) error { return syscall.Exec(exe, os.Args, os.Environ()) }
	updateBuild  = goBuild
	updateFindGo = findGo

	updateMu  sync.Mutex
	updateJob updateJobState
)

type updateJobState struct {
	State  string    `json:"state"` // "" | downloading | building | applying | failed
	Msg    string    `json:"msg,omitempty"`
	Target int       `json:"target,omitempty"`
	Since  time.Time `json:"since,omitempty"`
}

// updateState is the persistent record of the last update, and what the boot guard reads.
type updateState struct {
	State    string    `json:"state"` // applying | ok | rolled-back | failed
	From     int       `json:"from"`
	To       int       `json:"to"`
	Attempts int       `json:"attempts,omitempty"`
	Prev     string    `json:"prev,omitempty"`
	By       string    `json:"by,omitempty"`
	At       time.Time `json:"at"`
	Err      string    `json:"err,omitempty"`
}

var repoRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
var tagRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func curVersion() int { n, _ := strconv.Atoi(version()); return n }

// initUpdate is called once from main: it sets the state directory, clears what an interrupted update left behind and
// runs the boot guard.
func initUpdate(dataDir string) {
	updateDir = filepath.Join(dataDir, "update")
	if m, _ := filepath.Glob(filepath.Join(updateDir, "work-*")); len(m) > 0 {
		for _, p := range m {
			os.RemoveAll(p)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(updateDir, "upload-*")); len(m) > 0 {
		for _, p := range m {
			os.Remove(p)
		}
	}
	updateBoot()
}

func statePath() string { return filepath.Join(updateDir, "state.json") }

func readUpdateState() (updateState, bool) {
	var st updateState
	b, err := os.ReadFile(statePath())
	if err != nil || json.Unmarshal(b, &st) != nil {
		return st, false
	}
	return st, true
}

func writeUpdateState(st updateState) error {
	if err := os.MkdirAll(updateDir, 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(st)
	tmp := statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath())
}

// updateBoot is the boot guard. After an update the state is "applying" and names the version that should be running:
// each start of that version counts, one that stays up bootConfirmAfter is accepted, and one that keeps failing is
// replaced by the saved previous binary.
func updateBoot() {
	st, ok := readUpdateState()
	if !ok || st.State != "applying" {
		return
	}
	if strconv.Itoa(st.To) != version() { // some other build is running (a rollback, or a reinstall): nothing to guard
		st.State = "rolled-back"
		writeUpdateState(st)
		return
	}
	st.Attempts++
	if st.Attempts > maxBootAttempts {
		log.Printf("update: v%d failed to start %d times; restoring v%d", st.To, maxBootAttempts, st.From)
		rollbackUpdate(st, "the new version did not stay up")
		return
	}
	writeUpdateState(st)
	time.AfterFunc(bootConfirmAfter, func() {
		if st, ok := readUpdateState(); ok && st.State == "applying" && strconv.Itoa(st.To) == version() {
			st.State, st.Attempts = "ok", 0
			writeUpdateState(st)
			log.Printf("update: v%d is up", st.To)
		}
	})
}

// restorePrev puts the saved previous binary back in place of the current one.
func restorePrev(st updateState) error {
	exe, err := updateExe()
	if err != nil {
		return err
	}
	if st.Prev == "" {
		return errors.New("no previous binary was saved")
	}
	tmp := exe + ".new"
	if err := copyFile(st.Prev, tmp, 0o755); err != nil {
		return fmt.Errorf("previous binary: %w", err)
	}
	return os.Rename(tmp, exe)
}

func rollbackUpdate(st updateState, why string) {
	st.Err = why
	if err := restorePrev(st); err != nil {
		st.State, st.Err = "failed", why+"; restoring the previous version failed: "+err.Error()
		writeUpdateState(st)
		log.Printf("update: %s", st.Err)
		return
	}
	st.State = "rolled-back"
	writeUpdateState(st)
	exe, _ := updateExe()
	if err := updateExec(exe); err != nil {
		log.Printf("update: restart after rollback: %v", err)
	}
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}

// updatePrevPath is where the old binary is kept: the installer's $SHARE/goaduc.prev when that directory exists
// (<bin dir>/../share/goaduc), otherwise beside the binary.
func updatePrevPath(exe string) string {
	share := filepath.Join(filepath.Dir(exe), "..", "share", "goaduc")
	if st, err := os.Stat(share); err == nil && st.IsDir() {
		return filepath.Join(share, "goaduc.prev")
	}
	return exe + ".prev"
}

// findGo looks for a Go toolchain: PATH, the one the installer keeps in $SHARE/go, then /usr/local/go.
func findGo() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}
	cands := []string{"/usr/local/go/bin/go"}
	if exe, err := updateExe(); err == nil {
		cands = append([]string{filepath.Join(filepath.Dir(exe), "..", "share", "goaduc", "go", "bin", "go")}, cands...)
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func writableDir(dir string) bool {
	f, err := os.CreateTemp(dir, ".goaduc-write-*")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

// ---------- archive ----------

func badEntry(name string) bool {
	if name == "" || strings.ContainsAny(name, "\x00\\") || strings.HasPrefix(name, "/") {
		return true
	}
	for _, p := range strings.Split(name, "/") {
		if p == ".." {
			return true
		}
	}
	return false
}

// extractUpdate unpacks a release .tgz into dst, refusing anything that is not a plain file or directory inside it
// (links, devices, ".." or absolute names) and anything oversized. It returns the directory that holds go.mod: dst
// itself or the single top-level directory ("goaduc/" in our own archive, "<repo>-<tag>/" in GitHub's).
func extractUpdate(archive, dst string) (string, error) {
	f, err := os.Open(archive)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", errors.New("not a .tgz archive")
	}
	tr := tar.NewReader(gz)
	files, total := 0, int64(0)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("archive: %w", err)
		}
		switch h.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		if name == "." {
			continue
		}
		if badEntry(name) {
			return "", fmt.Errorf("archive: unsafe path %q", h.Name)
		}
		target := filepath.Join(dst, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return "", err
			}
		case tar.TypeReg:
			files++
			if files > maxUpdateFiles {
				return "", errors.New("archive: too many files")
			}
			if h.Size > maxUpdateFile {
				return "", fmt.Errorf("archive: %q is too large", h.Name)
			}
			total += h.Size
			if total > maxUpdateTotal {
				return "", errors.New("archive: too large when unpacked")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", err
			}
			out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				return "", fmt.Errorf("archive: %q: %w", h.Name, err)
			}
			if _, err := io.Copy(out, io.LimitReader(tr, h.Size)); err != nil {
				out.Close()
				return "", fmt.Errorf("archive: %w", err)
			}
			if err := out.Close(); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("archive: %q is a link or special file", h.Name)
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "go.mod")); err == nil {
		return dst, nil
	}
	es, _ := os.ReadDir(dst)
	var dirs []string
	for _, e := range es {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) == 1 {
		if _, err := os.Stat(filepath.Join(dst, dirs[0], "go.mod")); err == nil {
			return filepath.Join(dst, dirs[0]), nil
		}
	}
	return "", errors.New("archive has no go.mod: this is not a goaduc release")
}

// checkTree makes sure the tree looks like goaduc and is newer than what runs now; it returns the new version.
func checkTree(tree string) (int, error) {
	for _, f := range []string{"go.mod", "main.go", "VERSION", "static/index.html"} {
		if _, err := os.Stat(filepath.Join(tree, filepath.FromSlash(f))); err != nil {
			return 0, fmt.Errorf("this does not look like a goaduc release (%s is missing)", f)
		}
	}
	b, _ := os.ReadFile(filepath.Join(tree, "VERSION"))
	v := strings.TrimSpace(string(b))
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || strconv.Itoa(n) != v {
		return 0, fmt.Errorf("bad VERSION %q in the release", v)
	}
	switch cur := curVersion(); {
	case n == cur:
		return 0, fmt.Errorf("v%d is already installed", n)
	case n < cur:
		return 0, fmt.Errorf("v%d is older than the installed v%d (downgrade with install.sh --force)", n, cur)
	}
	return n, nil
}

// ---------- build ----------

func goBuild(goBin, tree, work, out string) error {
	ctx, cancel := context.WithTimeout(context.Background(), updateBuildTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, goBin, "build", "-trimpath", "-o", out, ".")
	cmd.Dir = tree
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOFLAGS=", "GOWORK=off",
		"GOCACHE="+filepath.Join(work, "gocache"), "GOPATH="+filepath.Join(work, "gopath"))
	if b, err := cmd.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(b))
		if len(msg) > 800 {
			msg = "…" + msg[len(msg)-800:]
		}
		if ctx.Err() != nil {
			return errors.New("build timed out")
		}
		return fmt.Errorf("go build failed: %s", msg)
	}
	return nil
}

func builtVersion(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, bin, "--version").Output()
	return strings.TrimSpace(string(b)), err
}

// ---------- the job ----------

func setJob(state, msg string, target int) {
	updateMu.Lock()
	updateJob = updateJobState{State: state, Msg: msg, Target: target, Since: time.Now()}
	updateMu.Unlock()
}

func jobBusy() bool {
	switch updateJob.State {
	case "downloading", "building", "applying":
		return true
	}
	return false
}

// startUpdate runs one update in the background. fetch puts the release archive at the path it is given.
func startUpdate(by string, target int, fetch func(dst string) error) error {
	updateMu.Lock()
	if jobBusy() {
		updateMu.Unlock()
		return errors.New("an update is already running")
	}
	updateJob = updateJobState{State: "downloading", Target: target, Since: time.Now()}
	updateMu.Unlock()
	go func() {
		if err := doUpdate(by, fetch); err != nil {
			log.Printf("update: %v", err)
			setJob("failed", err.Error(), 0)
			st, _ := readUpdateState()
			st.State, st.Err, st.By, st.At = "failed", err.Error(), by, time.Now().UTC()
			if st.From == 0 {
				st.From = curVersion()
			}
			writeUpdateState(st)
		}
	}()
	return nil
}

func doUpdate(by string, fetch func(dst string) error) error {
	if err := os.MkdirAll(updateDir, 0o700); err != nil {
		return err
	}
	work, err := os.MkdirTemp(updateDir, "work-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	arc := filepath.Join(work, "src.tgz")
	if err := fetch(arc); err != nil {
		return err
	}
	tree, err := extractUpdate(arc, filepath.Join(work, "tree"))
	if err != nil {
		return err
	}
	to, err := checkTree(tree)
	if err != nil {
		return err
	}
	goBin := updateFindGo()
	if goBin == "" {
		return errors.New("no Go toolchain found on this host (the installer keeps one in /usr/local/share/goaduc/go)")
	}
	setJob("building", "", to)
	out := filepath.Join(work, "goaduc.new")
	if err := updateBuild(goBin, tree, work, out); err != nil {
		return err
	}
	if got, err := builtVersion(out); err != nil || got != "goaduc v"+strconv.Itoa(to) {
		return fmt.Errorf("the built binary reports %q, expected goaduc v%d", got, to)
	}
	exe, err := updateExe()
	if err != nil {
		return err
	}
	prev := updatePrevPath(exe)
	if err := copyFile(exe, prev+".tmp", 0o755); err != nil {
		return fmt.Errorf("saving the current binary: %w", err)
	}
	if err := os.Rename(prev+".tmp", prev); err != nil {
		return err
	}
	if err := copyFile(out, exe+".new", 0o755); err != nil {
		return fmt.Errorf("writing the new binary: %w", err)
	}
	st := updateState{State: "applying", From: curVersion(), To: to, Prev: prev, By: by, At: time.Now().UTC()}
	if err := writeUpdateState(st); err != nil {
		os.Remove(exe + ".new")
		return err
	}
	if err := os.Rename(exe+".new", exe); err != nil {
		return err
	}
	setJob("applying", "", to)
	log.Printf("update: v%d -> v%d by %s; restarting", st.From, to, by)
	time.Sleep(updateRestartIn)
	if err := updateExec(exe); err != nil {
		restorePrev(st)
		st.State, st.Err = "failed", "restart failed: "+err.Error()
		writeUpdateState(st)
		return errors.New(st.Err)
	}
	return nil
}

// ---------- GitHub ----------

func updateClient() *http.Client { return &http.Client{Timeout: 5 * time.Minute} }

func updateGet(url string) (*http.Response, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "goaduc/"+version())
	resp, err := updateClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return resp, nil
}

func tagVersion(tag string) int {
	n, err := strconv.Atoi(strings.TrimPrefix(tag, "v"))
	if err != nil {
		return 0
	}
	return n
}

// latestTag is the newest published release, or failing that the highest v<number> tag.
func latestTag() (string, error) {
	if resp, err := updateGet(updateAPI + "/repos/" + updateRepo + "/releases/latest"); err == nil {
		var r struct {
			Tag string `json:"tag_name"`
		}
		err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r)
		resp.Body.Close()
		if err == nil && tagRe.MatchString(r.Tag) {
			return r.Tag, nil
		}
	}
	resp, err := updateGet(updateAPI + "/repos/" + updateRepo + "/tags?per_page=100")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var tags []struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tags); err != nil {
		return "", err
	}
	best, bn := "", 0
	for _, t := range tags {
		if n := tagVersion(t.Name); n > bn && tagRe.MatchString(t.Name) {
			best, bn = t.Name, n
		}
	}
	if best == "" {
		return "", errors.New("no release found in " + updateRepo)
	}
	return best, nil
}

func downloadTag(tag, dst string) error {
	if !tagRe.MatchString(tag) {
		return errors.New("bad tag name")
	}
	resp, err := updateGet(updateHost + "/" + updateRepo + "/archive/refs/tags/" + tag + ".tar.gz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxUpdateArchive+1))
	if err != nil {
		return err
	}
	if n > maxUpdateArchive {
		return errors.New("the download is larger than 32 MiB")
	}
	return nil
}

// ---------- API ----------

// isDomainAdmin: is the signed-in user, transitively, in Domain Admins or Enterprise Admins? (Update page, and the local
// fallback of the Recycle Bin purge.)
func isDomainAdmin(c *Conn, s *Session) (bool, error) {
	name := s.user
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	sam := name
	if i := strings.IndexByte(sam, '@'); i >= 0 {
		sam = sam[:i]
	}
	chain := func(group string) string {
		return "(memberOf:1.2.840.113556.1.4.1941:=" + EscapeFilter(group) + ")"
	}
	f := "(&(objectClass=user)(|(sAMAccountName=" + EscapeFilter(sam) + ")(userPrincipalName=" + EscapeFilter(name) + "))(|" +
		chain("CN=Domain Admins,CN=Users,"+s.base) + chain("CN=Enterprise Admins,CN=Users,"+s.base) + "))"
	es, _, err := c.Search(s.base, ScopeSub, f, []string{"sAMAccountName"}, 1)
	if err != nil {
		return false, err
	}
	return len(es) > 0, nil
}

func updateAllowed(s *Session) error {
	if updateDisabled {
		return errors.New("software updates are turned off (-no-update)")
	}
	var ok bool
	if err := s.With(func(c *Conn) (e error) { ok, e = isDomainAdmin(c, s); return e }); err != nil {
		return err
	}
	if !ok {
		return errors.New("only Domain Admins or Enterprise Admins can update goaduc")
	}
	return nil
}

func apiUpdateStatus(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	out := map[string]any{"version": curVersion(), "repo": updateRepo, "enabled": !updateDisabled}
	var admin bool
	if !updateDisabled {
		_ = s.With(func(c *Conn) (e error) { admin, e = isDomainAdmin(c, s); return nil })
	}
	why := ""
	switch exe, err := updateExe(); {
	case updateDisabled:
		why = "Updates are turned off (-no-update)."
	case !admin:
		why = "Only Domain Admins or Enterprise Admins can update."
	case updateFindGo() == "":
		why = "No Go toolchain found on this host."
	case err != nil || !writableDir(filepath.Dir(exe)):
		why = "The program directory is not writable by goaduc."
	}
	out["admin"], out["canApply"], out["why"] = admin, why == "", why
	updateMu.Lock()
	out["job"] = updateJob
	updateMu.Unlock()
	if st, ok := readUpdateState(); ok {
		out["last"] = st
	}
	return out, nil
}

// apiUpdateCheck asks GitHub for the newest release tag.
func apiUpdateCheck(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	if err := updateAllowed(s); err != nil {
		return nil, err
	}
	tag, err := latestTag()
	if err != nil {
		return nil, err
	}
	v := tagVersion(tag)
	return map[string]any{"tag": tag, "version": v, "newer": v > curVersion()}, nil
}

func apiUpdateOnline(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		Tag string `json:"tag"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := updateAllowed(s); err != nil {
		return nil, err
	}
	tag := in.Tag
	if tag == "" {
		var err error
		if tag, err = latestTag(); err != nil {
			return nil, err
		}
	}
	if !tagRe.MatchString(tag) {
		return nil, errors.New("bad tag name")
	}
	if err := startUpdate(s.user, tagVersion(tag), func(dst string) error { return downloadTag(tag, dst) }); err != nil {
		return nil, err
	}
	return map[string]any{"started": true, "tag": tag}, nil
}

// apiUpdateUpload takes the release archive as the raw request body (auth without reading the body into memory).
func apiUpdateUpload(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	if err := updateAllowed(s); err != nil {
		return nil, err
	}
	updateMu.Lock()
	busy := jobBusy()
	updateMu.Unlock()
	if busy {
		return nil, errors.New("an update is already running")
	}
	if err := os.MkdirAll(updateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(updateDir, "upload-*.tgz")
	if err != nil {
		return nil, err
	}
	n, err := io.Copy(f, http.MaxBytesReader(w, r.Body, maxUpdateArchive))
	f.Close()
	if err != nil || n == 0 {
		os.Remove(f.Name())
		if err == nil {
			err = errors.New("empty upload")
		}
		return nil, fmt.Errorf("upload: %w", err)
	}
	up := f.Name()
	if err := startUpdate(s.user, 0, func(dst string) error { return os.Rename(up, dst) }); err != nil {
		os.Remove(up)
		return nil, err
	}
	return map[string]any{"started": true}, nil
}

func registerUpdate(mux *http.ServeMux) {
	mux.HandleFunc("/api/update", auth(apiUpdateStatus))
	mux.HandleFunc("/api/update/check", auth(apiUpdateCheck))
	mux.HandleFunc("/api/update/online", auth(apiUpdateOnline))
	mux.HandleFunc("/api/update/upload", authStream(apiUpdateUpload))
}
