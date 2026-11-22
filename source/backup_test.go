package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupSlots(t *testing.T) {
	loc := time.UTC
	c := backupCfg{Freq: "daily", Time: "02:00"}
	at := func(d, h, m int) time.Time { return time.Date(2026, 11, d, h, m, 0, 0, loc) }
	if s := lastSlot(c, at(21, 3, 0)); !s.Equal(at(21, 2, 0)) {
		t.Fatal(s)
	}
	if s := lastSlot(c, at(21, 1, 0)); !s.Equal(at(20, 2, 0)) {
		t.Fatal(s)
	}
	if s := nextSlot(c, at(21, 3, 0)); !s.Equal(at(22, 2, 0)) {
		t.Fatal(s)
	}
	w := backupCfg{Freq: "weekly", Time: "23:30", Weekday: 0} // Sundays; 2026-11-22 is a Sunday
	if s := lastSlot(w, at(25, 9, 0)); !s.Equal(at(22, 23, 30)) {
		t.Fatal(s)
	}
	if s := lastSlot(w, at(22, 23, 0)); !s.Equal(at(15, 23, 30)) {
		t.Fatal(s)
	}
	if s := nextSlot(w, at(25, 9, 0)); !s.Equal(at(29, 23, 30)) {
		t.Fatal(s)
	}
}

func TestBackupRotate(t *testing.T) {
	dir := t.TempDir()
	oroot := backupRoot
	t.Cleanup(func() { backupRoot = oroot })
	backupRoot = dir
	base := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		p := filepath.Join(dir, fmt.Sprintf("samba-backup-x-%d.tar.bz2", i))
		os.WriteFile(p, []byte("x"), 0o600)
		os.Chtimes(p, base.Add(time.Duration(i)*time.Hour), base.Add(time.Duration(i)*time.Hour))
	}
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("keep me"), 0o600)
	os.Mkdir(filepath.Join(dir, "old.tar.bz2"), 0o700) // a folder is never touched
	gone, err := backupRotate(dir, 4)
	if err != nil || fmt.Sprint(gone) != "[samba-backup-x-0.tar.bz2 samba-backup-x-1.tar.bz2]" {
		t.Fatalf("%v %v", gone, err)
	}
	if fs := backupFiles(dir); len(fs) != 4 || fs[0].Name != "samba-backup-x-5.tar.bz2" {
		t.Fatalf("%v", fs)
	}
	for _, n := range []string{"notes.txt", "old.tar.bz2"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Fatal(n, "was removed")
		}
	}
	if gone, _ := backupRotate(dir, 10); len(gone) != 0 {
		t.Fatal("removed below the limit")
	}
}

func TestBackupAPI(t *testing.T) {
	c, d := setup(t)
	dataDir := t.TempDir()
	initBackup(dataDir)
	ocan, oexec, onow := backupCanRun, backupExec, backupNow
	t.Cleanup(func() { backupCanRun, backupExec, backupNow = ocan, oexec, onow; initBackup(t.TempDir()) })
	backupCanRun = func() string { return "" }
	oroot := backupRoot
	t.Cleanup(func() { backupRoot = oroot })
	backupRoot = t.TempDir()
	out := filepath.Join(backupRoot, "ad")
	n := 0
	backupExec = func(dir string) (string, error) {
		n++
		os.MkdirAll(dir, 0o700)
		name := fmt.Sprintf("samba-backup-samdom-%03d.tar.bz2", n)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
			return "", err
		}
		ts := time.Date(2026, 11, 1, n, 0, 0, 0, time.UTC)
		os.Chtimes(p, ts, ts)
		return name, nil
	}
	save := map[string]any{"enabled": false, "dir": out, "keep": 3, "freq": "daily", "time": "02:00", "weekday": 0}

	// not a Domain/Enterprise Admin: nothing is saved or run
	c.fail("POST", "/api/settings/backup/save", save, "only Domain Admins")
	c.fail("POST", "/api/settings/backup/run", nil, "only Domain Admins")
	if st := c.ok("GET", "/api/settings/backup", nil); st["admin"] != false || st["canRun"] != false {
		t.Fatalf("%v", st)
	}
	if n != 0 {
		t.Fatal("ran for a non-admin")
	}

	d.put("CN=admin,CN=Users,"+tBase, "objectClass", "top", "objectClass", "person", "objectClass", "user", "sAMAccountName", "admin",
		"userPrincipalName", "admin@samdom.example.com", "memberOf", "CN=Domain Admins,CN=Users,"+tBase)

	for _, bad := range []map[string]any{
		{"dir": "relative", "keep": 3, "freq": "daily", "time": "02:00"}, {"dir": "/", "keep": 3, "freq": "daily", "time": "02:00"},
		{"dir": "/etc", "keep": 3, "freq": "daily", "time": "02:00"}, {"dir": out + "/../../etc", "keep": 3, "freq": "daily", "time": "02:00"},
		{"dir": backupRoot + "x/ad", "keep": 3, "freq": "daily", "time": "02:00"},
		{"dir": out, "keep": 0, "freq": "daily", "time": "02:00"}, {"dir": out, "keep": 3, "freq": "hourly", "time": "02:00"},
		{"dir": out, "keep": 3, "freq": "daily", "time": "25:00"}, {"dir": out, "keep": 3, "freq": "daily", "time": "2:00"}} {
		c.fail("POST", "/api/settings/backup/save", bad, "")
	}
	st := c.ok("POST", "/api/settings/backup/save", save)
	if st["admin"] != true || st["canRun"] != true || list(st["files"]) == nil {
		t.Fatalf("%v", st)
	}
	if b, err := os.ReadFile(filepath.Join(dataDir, "backup.json")); err != nil || len(b) == 0 {
		t.Fatal("settings not stored")
	}

	waitIdle := func() map[string]any {
		for i := 0; i < 200; i++ {
			if s := c.ok("GET", "/api/settings/backup", nil); s["running"] == false {
				return s
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("backup never finished")
		return nil
	}
	for i := 0; i < 5; i++ { // five manual runs, keep 3: the oldest two are rotated away
		c.ok("POST", "/api/settings/backup/run", nil)
		waitIdle()
	}
	s := waitIdle()
	if fs := list(s["files"]); len(fs) != 3 || fs[0].(map[string]any)["name"] != "samba-backup-samdom-005.tar.bz2" || fs[2].(map[string]any)["name"] != "samba-backup-samdom-003.tar.bz2" {
		t.Fatalf("%v", fs)
	}
	if last := s["last"].(map[string]any); last["ok"] != true || last["trigger"] != "manual" || last["by"] != "admin@samdom.example.com" {
		t.Fatalf("%v", last)
	}

	// a failing run keeps the existing backups and reports why
	backupExec = func(string) (string, error) { return "", fmt.Errorf("samba-tool: boom") }
	c.ok("POST", "/api/settings/backup/run", nil)
	s = waitIdle()
	if last := s["last"].(map[string]any); last["ok"] != false || last["error"] != "samba-tool: boom" || len(list(s["files"])) != 3 {
		t.Fatalf("%v", s)
	}
	// a host that cannot run it says so
	backupCanRun = func() string { return "not root" }
	c.fail("POST", "/api/settings/backup/run", nil, "not root")

	// schedule: turning it on does not run for a slot that already passed; the next slot does
	backupCanRun = func() string { return "" }
	backupExec = func(dir string) (string, error) {
		n++
		name := fmt.Sprintf("samba-backup-samdom-%03d.tar.bz2", n)
		return name, os.WriteFile(filepath.Join(dir, name), []byte("d"), 0o600)
	}
	clock := time.Date(2026, 11, 21, 12, 0, 0, 0, time.Local)
	backupNow = func() time.Time { return clock }
	save["enabled"] = true
	st = c.ok("POST", "/api/settings/backup/save", save)
	if st["next"] == nil {
		t.Fatal("no next run")
	}
	before := n
	backupTick()
	time.Sleep(50 * time.Millisecond)
	if n != before {
		t.Fatal("ran for a slot before it was turned on")
	}
	clock = time.Date(2026, 11, 22, 2, 0, 5, 0, time.Local)
	backupTick()
	waitIdle()
	if n != before+1 {
		t.Fatal("scheduled run did not happen")
	}
	if last := c.ok("GET", "/api/settings/backup", nil)["last"].(map[string]any); last["trigger"] != "schedule" {
		t.Fatalf("%v", last)
	}
	backupTick() // the same slot never runs twice
	time.Sleep(50 * time.Millisecond)
	if n != before+1 {
		t.Fatal("ran twice for one slot")
	}
}

func TestBackupDirConfined(t *testing.T) {
	oroot := backupRoot
	t.Cleanup(func() { backupRoot = oroot })
	backupRoot = "/var/backups"
	for in, want := range map[string]bool{"/var/backups": true, "/var/backups/samba-ad": true, "/var/backups/a/../b": true,
		"/var/backups/../etc": false, "/var/backupsx": false, "/etc": false, "/": false, "var/backups": false, "": false} {
		if _, ok := backupDir(in); ok != want {
			t.Errorf("backupDir(%q) = %v, want %v", in, ok, want)
		}
	}
	if fs := backupFiles("/etc"); len(fs) != 0 {
		t.Fatal("listed outside the backup root")
	}
	if _, err := backupRotate("/etc", 1); err == nil {
		t.Fatal("rotated outside the backup root")
	}
	if _, err := backupExec("/etc"); err == nil {
		t.Fatal("ran outside the backup root")
	}
}
