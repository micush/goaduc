package main

// Settings > Backup: the Samba offline domain backup (samba-tool domain backup offline), on demand or on a schedule,
// with the newest N backup files kept and older ones removed (first in, first out).
//
// Running it is a local operation on the DC, so, like the updater and the Recycle Bin local fallback, only a verified
// Domain/Enterprise Admin can run it or change the schedule (checked over their own LDAP connection), and it needs
// goaduc to run as root on a DC with samba-tool. The schedule is stored in backup.json in the data directory and is
// carried out by goaduc itself, as the account goaduc runs as. Backups hold password hashes and secrets, so the folder is
// created 0700 and goaduc never offers the files for download; copy them off the DC with your own tools.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type backupCfg struct {
	Enabled bool   `json:"enabled"`
	Dir     string `json:"dir"`
	Keep    int    `json:"keep"`
	Freq    string `json:"freq"`    // daily | weekly
	Time    string `json:"time"`    // HH:MM, server local time
	Weekday int    `json:"weekday"` // 0 = Sunday, for weekly
	SetBy   string `json:"setBy,omitempty"`
}

type backupLast struct {
	Time    time.Time `json:"time"`
	OK      bool      `json:"ok"`
	File    string    `json:"file,omitempty"`
	Size    int64     `json:"size,omitempty"`
	Error   string    `json:"error,omitempty"`
	Trigger string    `json:"trigger"` // schedule | manual
	By      string    `json:"by,omitempty"`
	Removed []string  `json:"removed,omitempty"`
}

type backupState struct {
	Cfg      backupCfg   `json:"cfg"`
	Last     *backupLast `json:"last,omitempty"`
	LastSlot time.Time   `json:"lastSlot"`
}

// backupRoot is the folder backups must live under (-backup-root); the folder chosen in Settings can't point outside it.
var backupRoot = "/var/backups"

// backupDir returns dir cleaned, and whether it is backupRoot itself or inside it. Every function that touches the
// folder goes through this, so a stored or submitted path can never reach elsewhere on the disk.
func backupDir(dir string) (string, bool) {
	root := filepath.Clean(backupRoot)
	d := filepath.Clean(dir)
	if !filepath.IsAbs(d) || strings.ContainsRune(d, 0) || d == "/" {
		return "", false
	}
	if d != root && !strings.HasPrefix(d, root+string(filepath.Separator)) {
		return "", false
	}
	return d, true
}

var (
	backupMu      sync.Mutex // guards backupSt, backupPath, backupRunning
	backupSt      backupState
	backupPath    string
	backupRunning bool
	backupNow     = time.Now // tests replace it
)

func defaultBackupCfg() backupCfg {
	return backupCfg{Dir: filepath.Join(backupRoot, "samba-ad"), Keep: 7, Freq: "daily", Time: "02:00"}
}

func initBackup(dataDir string) {
	backupMu.Lock()
	defer backupMu.Unlock()
	backupPath = filepath.Join(dataDir, "backup.json")
	backupSt = backupState{Cfg: defaultBackupCfg()}
	if b, err := os.ReadFile(backupPath); err == nil {
		_ = json.Unmarshal(b, &backupSt)
	}
	if backupSt.Cfg.Dir == "" || backupSt.Cfg.Keep < 1 {
		d := defaultBackupCfg()
		if backupSt.Cfg.Dir == "" {
			backupSt.Cfg.Dir = d.Dir
		}
		if backupSt.Cfg.Keep < 1 {
			backupSt.Cfg.Keep = d.Keep
		}
	}
}

// backupSave writes the state; the caller holds backupMu.
func backupSave() error {
	if backupPath == "" {
		return nil
	}
	b, _ := json.MarshalIndent(backupSt, "", "  ")
	if err := os.MkdirAll(filepath.Dir(backupPath), 0o700); err != nil {
		return err
	}
	tmp := backupPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, backupPath)
}

func parseHM(s string) (h, m int, ok bool) {
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil || len(s) != 5 || s[2] != ':' {
		return 0, 0, false
	}
	return h, m, h >= 0 && h < 24 && m >= 0 && m < 60
}

// lastSlot is the most recent scheduled moment at or before now.
func lastSlot(c backupCfg, now time.Time) time.Time {
	h, m, _ := parseHM(c.Time)
	t := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if c.Freq == "weekly" {
		for t.After(now) || int(t.Weekday()) != c.Weekday {
			t = time.Date(t.Year(), t.Month(), t.Day()-1, h, m, 0, 0, now.Location())
		}
		return t
	}
	if t.After(now) {
		t = time.Date(t.Year(), t.Month(), t.Day()-1, h, m, 0, 0, now.Location())
	}
	return t
}

func nextSlot(c backupCfg, now time.Time) time.Time {
	h, m, _ := parseHM(c.Time)
	t := lastSlot(c, now)
	if c.Freq == "weekly" {
		return time.Date(t.Year(), t.Month(), t.Day()+7, h, m, 0, 0, now.Location())
	}
	return time.Date(t.Year(), t.Month(), t.Day()+1, h, m, 0, 0, now.Location())
}

func validBackupCfg(c *backupCfg) error {
	c.Dir = strings.TrimSpace(c.Dir)
	if c.Dir == "" || !filepath.IsAbs(c.Dir) || strings.ContainsRune(c.Dir, 0) {
		return errors.New("the backup folder must be an absolute path")
	}
	d, ok := backupDir(c.Dir)
	if !ok {
		return errors.New("the backup folder must be inside " + filepath.Clean(backupRoot) + " (change it with -backup-root)")
	}
	c.Dir = d
	if c.Keep < 1 || c.Keep > 365 {
		return errors.New("keep between 1 and 365 backups")
	}
	if c.Freq != "daily" && c.Freq != "weekly" {
		return errors.New("choose daily or weekly")
	}
	if _, _, ok := parseHM(c.Time); !ok {
		return errors.New("the time must be HH:MM")
	}
	if c.Weekday < 0 || c.Weekday > 6 {
		return errors.New("bad weekday")
	}
	return nil
}

// backupCanRun says why this host cannot run the backup, or "" when it can. A variable so tests can replace it.
var backupCanRun = func() string {
	if os.Geteuid() != 0 {
		return "goaduc is not running as root, which samba-tool domain backup offline needs."
	}
	if _, err := exec.LookPath("samba-tool"); err != nil {
		return "samba-tool was not found on this host."
	}
	return ""
}

// backupExec runs the backup into dir and returns the file it made. A variable so tests can replace it.
var backupExec = func(dir string) (string, error) {
	rel, rerr := filepath.Rel(filepath.Clean(backupRoot), filepath.Clean(dir)) // the folder as a path below the backup root
	if rerr != nil || !filepath.IsLocal(rel) {
		return "", errors.New("the backup folder is outside " + backupRoot)
	}
	dir = filepath.Join(backupRoot, rel)
	bin, err := exec.LookPath("samba-tool")
	if err != nil {
		return "", errors.New("samba-tool not found")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	before := map[string]bool{}
	for _, f := range backupFiles(dir) {
		before[f.Name] = true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	if out, err := exec.CommandContext(ctx, bin, "domain", "backup", "offline", "--targetdir="+dir).CombinedOutput(); err != nil {
		return "", fmt.Errorf("samba-tool: %v: %s", err, strings.TrimSpace(string(out)))
	}
	var made []backupItem
	for _, f := range backupFiles(dir) {
		if !before[f.Name] {
			made = append(made, f)
		}
	}
	if len(made) == 0 {
		return "", errors.New("samba-tool finished but no new backup file appeared in " + dir)
	}
	return made[0].Name, nil // newest first
}

type backupItem struct {
	Name string    `json:"name"`
	Size int64     `json:"size"`
	Time time.Time `json:"time"`
}

// backupFiles lists the *.tar.bz2 files in dir, newest first.
func backupFiles(dir string) []backupItem {
	out := []backupItem{}
	rel, rerr := filepath.Rel(filepath.Clean(backupRoot), filepath.Clean(dir)) // the folder as a path below the backup root
	if rerr != nil || !filepath.IsLocal(rel) {
		return out
	}
	dir = filepath.Join(backupRoot, rel)
	es, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range es {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".tar.bz2") {
			continue
		}
		if fi, err := e.Info(); err == nil {
			out = append(out, backupItem{e.Name(), fi.Size(), fi.ModTime()})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Time.Equal(out[j].Time) {
			return out[i].Time.After(out[j].Time)
		}
		return out[i].Name > out[j].Name
	})
	return out
}

// backupRotate removes the oldest *.tar.bz2 files in dir until keep remain, and returns their names.
func backupRotate(dir string, keep int) ([]string, error) {
	rel, rerr := filepath.Rel(filepath.Clean(backupRoot), filepath.Clean(dir)) // the folder as a path below the backup root
	if rerr != nil || !filepath.IsLocal(rel) {
		return nil, errors.New("the backup folder is outside " + backupRoot)
	}
	dir = filepath.Join(backupRoot, rel)
	fs := backupFiles(dir)
	var gone []string
	for i := len(fs) - 1; i >= keep; i-- { // oldest last
		if err := os.Remove(filepath.Join(dir, fs[i].Name)); err != nil {
			return gone, err
		}
		gone = append(gone, fs[i].Name)
	}
	return gone, nil
}

// backupDo runs one backup and rotation and records the outcome. Only one runs at a time.
func backupDo(trigger, by string) (*backupLast, error) {
	backupMu.Lock()
	if backupRunning {
		backupMu.Unlock()
		return nil, errors.New("a backup is already running")
	}
	backupRunning = true
	cfg := backupSt.Cfg
	backupMu.Unlock()

	res := &backupLast{Time: backupNow(), Trigger: trigger, By: by}
	if why := backupCanRun(); why != "" {
		res.Error = why
	} else if name, err := backupExec(cfg.Dir); err != nil {
		res.Error = err.Error()
	} else {
		res.OK, res.File = true, name
		res.Size = backupSize(cfg.Dir, name)
		var rerr error
		if res.Removed, rerr = backupRotate(cfg.Dir, cfg.Keep); rerr != nil {
			res.Error = "backup made, but removing old ones failed: " + rerr.Error()
		}
	}
	backupMu.Lock()
	backupSt.Last = res
	backupRunning = false
	serr := backupSave()
	backupMu.Unlock()
	if res.OK {
		log.Printf("backup (%s): wrote %s, removed %d old", trigger, res.File, len(res.Removed))
	} else {
		log.Printf("backup (%s) failed: %s", trigger, res.Error)
	}
	if serr != nil {
		log.Printf("backup: saving state: %v", serr)
	}
	return res, nil
}

// backupTick starts a scheduled backup when a slot has come due since the last one.
func backupTick() {
	backupMu.Lock()
	c, due := backupSt.Cfg, false
	if c.Enabled && !backupRunning {
		if s := lastSlot(c, backupNow()); s.After(backupSt.LastSlot) {
			backupSt.LastSlot, due = s, true
			_ = backupSave()
		}
	}
	backupMu.Unlock()
	if due {
		go backupDo("schedule", c.SetBy)
	}
}

func startBackupScheduler() {
	go func() {
		for range time.Tick(30 * time.Second) {
			backupTick()
		}
	}()
}

// ---------- API ----------

func backupAllowed(s *Session) error {
	var ok bool
	if err := s.With(func(c *Conn) (e error) { ok, e = isDomainAdmin(c, s); return e }); err != nil {
		return err
	}
	if !ok {
		return errors.New("only Domain Admins or Enterprise Admins can change or run backups")
	}
	return nil
}

func apiBackup(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var admin bool
	_ = s.With(func(c *Conn) (e error) { admin, e = isDomainAdmin(c, s); return nil })
	why := backupCanRun()
	if !admin {
		why = "Only Domain Admins or Enterprise Admins can change or run backups."
	}
	backupMu.Lock()
	st, running := backupSt, backupRunning
	backupMu.Unlock()
	out := map[string]any{"cfg": st.Cfg, "last": st.Last, "running": running, "admin": admin, "canRun": why == "", "why": why,
		"files": backupFiles(st.Cfg.Dir)}
	if st.Cfg.Enabled {
		out["next"] = nextSlot(st.Cfg, backupNow())
	}
	return out, nil
}

func apiBackupSave(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in backupCfg
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := backupAllowed(s); err != nil {
		return nil, err
	}
	if err := validBackupCfg(&in); err != nil {
		return nil, err
	}
	in.SetBy = s.user
	backupMu.Lock()
	was := backupSt.Cfg.Enabled
	backupSt.Cfg = in
	if in.Enabled && !was || in.Enabled && backupSt.LastSlot.IsZero() {
		backupSt.LastSlot = lastSlot(in, backupNow()) // start from now; don't run for a slot that passed before it was turned on
	}
	err := backupSave()
	backupMu.Unlock()
	if err != nil {
		return nil, err
	}
	log.Printf("backup: settings changed by %s (enabled=%v dir=%s keep=%d %s %s)", s.user, in.Enabled, in.Dir, in.Keep, in.Freq, in.Time)
	return apiBackup(w, r, s)
}

func apiBackupRun(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	if err := backupAllowed(s); err != nil {
		return nil, err
	}
	if why := backupCanRun(); why != "" {
		return nil, errors.New(why)
	}
	backupMu.Lock()
	busy := backupRunning
	backupMu.Unlock()
	if busy {
		return nil, errors.New("a backup is already running")
	}
	log.Printf("backup: started by %s", s.user)
	go backupDo("manual", s.user)
	return map[string]any{"started": true}, nil
}

func registerBackup(mux *http.ServeMux) {
	mux.HandleFunc("/api/settings/backup", auth(apiBackup))
	mux.HandleFunc("/api/settings/backup/save", auth(apiBackupSave))
	mux.HandleFunc("/api/settings/backup/run", auth(apiBackupRun))
}

// backupSize is the size of a backup file, 0 if it can't be read or is outside the backup folder.
func backupSize(dir, name string) int64 {
	for _, f := range backupFiles(dir) { // only files the confined listing returns
		if f.Name == name {
			return f.Size
		}
	}
	return 0
}
