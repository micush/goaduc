package main

// SYSVOL side of Group Policy: the GPT folder of each GPO (GPT.INI, Machine/, User/), Registry.pol, GptTmpl.inf and
// plain files. goaduc must run on the domain controller, as root, for any of this to work (-sysvol / ADUC_SYSVOL).
// Reads need the signed-in user to be able to read the GPO in AD; writes go through gpoCommit (gpo.go).

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// sysvolRoot is the SYSVOL share's directory on this host ("" = Group Policy settings can't be edited).
var sysvolRoot string

type sysvolStatus struct {
	Available bool   `json:"available"`
	Writable  bool   `json:"writable"`
	Path      string `json:"path"`
}

func sysvolInfo(s *Session) sysvolStatus {
	pol, err := policiesDir(s)
	if err != nil {
		return sysvolStatus{}
	}
	return sysvolStatus{Available: true, Writable: syscall.Access(pol, 2) == nil, Path: pol}
}

// resolveCI joins rel below base matching each existing component case-insensitively (SYSVOL files come from Windows
// tools and Samba is configured case-insensitively, the Linux directory itself is not). exists is false when some
// component is missing; the remainder is appended as given.
func resolveCI(base, rel string) (full string, exists bool) {
	cur := base
	exists = true
	for _, comp := range strings.Split(rel, "/") {
		if comp == "" {
			continue
		}
		next := filepath.Join(cur, comp)
		if !exists {
			cur = next
			continue
		}
		if _, err := os.Lstat(next); err == nil {
			cur = next
			continue
		}
		found := false
		if es, err := os.ReadDir(cur); err == nil {
			for _, e := range es {
				if strings.EqualFold(e.Name(), comp) {
					cur, found = filepath.Join(cur, e.Name()), true
					break
				}
			}
		}
		if !found {
			cur, exists = next, false
		}
	}
	return cur, exists
}

func policiesDir(s *Session) (string, error) {
	if sysvolRoot == "" {
		return "", errors.New("SYSVOL is not available: goaduc must run on the domain controller (set -sysvol / ADUC_SYSVOL)")
	}
	p, ok := resolveCI(sysvolRoot, dnsDomainOf(s.base)+"/Policies")
	if st, err := os.Stat(p); !ok || err != nil || !st.IsDir() {
		return "", fmt.Errorf("SYSVOL folder %s/Policies not found", filepath.Join(sysvolRoot, dnsDomainOf(s.base)))
	}
	return p, nil
}

func gpoDir(s *Session, guid string) (string, error) {
	pol, err := policiesDir(s)
	if err != nil {
		return "", err
	}
	d, ok := resolveCI(pol, guid)
	if st, err := os.Stat(d); !ok || err != nil || !st.IsDir() {
		return "", errors.New("this GPO has no folder in SYSVOL")
	}
	return d, nil
}

// gpoFor validates the identifier and checks that the signed-in user can read the GPO in AD.
func gpoFor(s *Session, raw string) (guid, dir string, err error) {
	if guid, err = normGUID(raw); err != nil {
		return
	}
	if err = s.With(func(c *Conn) error { _, e := c.Read(gpoDN(s, guid), []string{"name"}); return e }); err != nil {
		return
	}
	dir, err = gpoDir(s, guid)
	return
}

// ---------- GPT.INI ----------

var gptVerRe = regexp.MustCompile(`(?mi)^\s*Version\s*=\s*(\d+)`)

func readGPTVersion(dir string) (int64, bool) {
	p, ok := resolveCI(dir, "GPT.INI")
	if !ok {
		return 0, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return 0, false
	}
	txt, _ := decodeText(b)
	if m := gptVerRe.FindStringSubmatch(txt); m != nil {
		n, _ := strconv.ParseInt(m[1], 10, 64)
		return n, true
	}
	return 0, false
}

func writeGPTVersion(dir string, v int64) error {
	p, _ := resolveCI(dir, "GPT.INI")
	txt := ""
	if b, err := os.ReadFile(p); err == nil {
		txt, _ = decodeText(b)
	}
	line := "Version=" + strconv.FormatInt(v, 10)
	switch {
	case gptVerRe.MatchString(txt):
		txt = gptVerRe.ReplaceAllString(txt, line)
	case strings.Contains(strings.ToLower(txt), "[general]"):
		i := strings.Index(strings.ToLower(txt), "[general]") + len("[general]")
		txt = txt[:i] + "\r\n" + line + txt[i:]
	default:
		txt = "[General]\r\n" + line + "\r\n" + txt
	}
	like, _ := os.Stat(dir)
	return atomicWrite(p, []byte(txt), 0o644, like)
}

func createGPOFiles(pol, guid string) error {
	dir := filepath.Join(pol, guid)
	like, _ := os.Stat(pol)
	if err := os.Mkdir(dir, 0o755); err != nil {
		return err
	}
	chownLike(dir, like)
	for _, sub := range []string{"Machine", "User"} {
		d := filepath.Join(dir, sub)
		if err := os.Mkdir(d, 0o755); err != nil {
			os.RemoveAll(dir)
			return err
		}
		chownLike(d, like)
	}
	if err := atomicWrite(filepath.Join(dir, "GPT.INI"), []byte("[General]\r\nVersion=0\r\n"), 0o644, like); err != nil {
		os.RemoveAll(dir)
		return err
	}
	return nil
}

func removeGPOFiles(s *Session, guid string) error {
	pol, err := policiesDir(s)
	if err != nil {
		return err
	}
	d, ok := resolveCI(pol, guid)
	if !ok {
		return nil
	}
	if filepath.Dir(d) != filepath.Clean(pol) {
		return errors.New("refusing to remove a folder outside Policies")
	}
	return os.RemoveAll(d)
}

// ---------- file helpers ----------

func chownLike(path string, like os.FileInfo) {
	if like == nil {
		return
	}
	if st, ok := like.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(st.Uid), int(st.Gid))
	}
}

// atomicWrite writes via a temporary file in the same folder, keeping the old file's mode and owner when there is one
// (otherwise perm and the owner of `like`, normally the parent folder).
func atomicWrite(path string, data []byte, perm os.FileMode, like os.FileInfo) error {
	if old, err := os.Stat(path); err == nil {
		perm, like = old.Mode().Perm(), old
	}
	tmp := path + ".goaduc-tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	_ = os.Chmod(tmp, perm)
	chownLike(tmp, like)
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func mkdirAllLike(dir string) error {
	var missing []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Stat(d); err == nil {
			break
		}
		missing = append(missing, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		parent, _ := os.Stat(filepath.Dir(missing[i]))
		if err := os.Mkdir(missing[i], 0o755); err != nil {
			return err
		}
		chownLike(missing[i], parent)
	}
	return nil
}

func etagOf(b []byte, exists bool) string {
	if !exists {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// safeRel validates a path below a GPO folder: forward slashes, no "." or "..", no empty parts.
func safeRel(p string) (string, error) {
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.ContainsRune(p, 0) || len(p) > 400 {
		return "", errors.New("invalid path")
	}
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c == "" {
			continue
		}
		if c == "." || c == ".." || strings.HasSuffix(c, ".goaduc-tmp") {
			return "", errors.New("invalid path")
		}
		out = append(out, c)
	}
	return strings.Join(out, "/"), nil
}

// gpoPath resolves rel inside the GPO folder and refuses anything that leaves it through a symbolic link.
func gpoPath(dir, rel string) (full string, exists bool, err error) {
	if rel, err = safeRel(rel); err != nil {
		return
	}
	full, exists = resolveCI(dir, rel)
	realDir, e := filepath.EvalSymlinks(dir)
	if e != nil {
		return "", false, e
	}
	check := full
	if !exists {
		check = filepath.Dir(full)
	} else if st, e := os.Lstat(full); e == nil && st.Mode()&os.ModeSymlink != 0 {
		return "", false, errors.New("symbolic links are not followed")
	}
	if rc, e := filepath.EvalSymlinks(check); e == nil {
		if rc != realDir && !strings.HasPrefix(rc, realDir+string(filepath.Separator)) {
			return "", false, errors.New("path escapes the GPO folder")
		}
	}
	return full, exists, nil
}

// scopeOf says which half of the GPO a path belongs to; only Machine/ and User/ may be changed.
func scopeOf(rel string) (machine, user bool, err error) {
	rel, err = safeRel(rel)
	if err != nil || rel == "" {
		return false, false, errors.New("invalid path")
	}
	switch strings.ToLower(strings.SplitN(rel, "/", 2)[0]) {
	case "machine":
		return true, false, nil
	case "user":
		return false, true, nil
	}
	return false, false, errors.New("only the Machine and User folders can be changed")
}

// ---------- text encodings ----------

// decodeText returns the text of a file and its encoding name (utf-8, utf-8-bom, utf-16le, utf-16be).
func decodeText(b []byte) (string, string) {
	switch {
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		return u16s(b[2:], binary.LittleEndian), "utf-16le"
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		return u16s(b[2:], binary.BigEndian), "utf-16be"
	case len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF:
		return string(b[3:]), "utf-8-bom"
	}
	return string(b), "utf-8"
}

func u16s(b []byte, o binary.ByteOrder) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = o.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

func encodeText(s, encName string) []byte {
	switch encName {
	case "utf-16le", "utf-16be":
		var o binary.AppendByteOrder = binary.LittleEndian
		bom := []byte{0xFF, 0xFE}
		if encName == "utf-16be" {
			o, bom = binary.BigEndian, []byte{0xFE, 0xFF}
		}
		u := utf16.Encode([]rune(s))
		out := append([]byte{}, bom...)
		for _, v := range u {
			out = o.AppendUint16(out, v)
		}
		return out
	case "utf-8-bom":
		return append([]byte{0xEF, 0xBB, 0xBF}, s...)
	}
	return []byte(s)
}

// isTextFile reports whether b can be edited as text, with the text and its encoding.
func isTextFile(b []byte) (string, string, bool) {
	txt, enc := decodeText(b)
	if strings.HasPrefix(enc, "utf-16") {
		return txt, enc, !strings.ContainsRune(txt, 0)
	}
	if !utf8.ValidString(txt) || strings.ContainsRune(txt, 0) {
		return "", "", false
	}
	return txt, enc, true
}

// ---------- Registry.pol ----------

type PolEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  uint32 `json:"type"`
	Data  string `json:"data"`
}

const (
	regSZ, regExpandSZ, regBinary, regDWord, regMultiSZ, regQWord = 1, 2, 3, 4, 7, 11
)

func polReadZ(b []byte, p int) (string, int, error) {
	var u []uint16
	for {
		if p+2 > len(b) {
			return "", 0, errors.New("truncated Registry.pol")
		}
		v := binary.LittleEndian.Uint16(b[p:])
		p += 2
		if v == 0 {
			return string(utf16.Decode(u)), p, nil
		}
		u = append(u, v)
	}
}

func polExpect(b []byte, p int, c uint16) (int, error) {
	if p+2 > len(b) || binary.LittleEndian.Uint16(b[p:]) != c {
		return 0, fmt.Errorf("malformed Registry.pol near byte %d", p)
	}
	return p + 2, nil
}

// parsePol decodes a Registry.pol file ([MS-GPREG] 2.2): "PReg", version 1, then [key;value;type;size;data] records.
func parsePol(b []byte) ([]PolEntry, error) {
	out := []PolEntry{}
	if len(b) == 0 {
		return out, nil
	}
	if len(b) < 8 || string(b[:4]) != "PReg" || binary.LittleEndian.Uint32(b[4:]) != 1 {
		return nil, errors.New("not a Registry.pol file")
	}
	p := 8
	for p < len(b) {
		var err error
		var e PolEntry
		if p, err = polExpect(b, p, '['); err != nil {
			return nil, err
		}
		if e.Key, p, err = polReadZ(b, p); err != nil {
			return nil, err
		}
		if p, err = polExpect(b, p, ';'); err != nil {
			return nil, err
		}
		if e.Value, p, err = polReadZ(b, p); err != nil {
			return nil, err
		}
		if p, err = polExpect(b, p, ';'); err != nil {
			return nil, err
		}
		if p+4 > len(b) {
			return nil, errors.New("truncated Registry.pol")
		}
		e.Type = binary.LittleEndian.Uint32(b[p:])
		p += 4
		if p, err = polExpect(b, p, ';'); err != nil {
			return nil, err
		}
		if p+4 > len(b) {
			return nil, errors.New("truncated Registry.pol")
		}
		size := int(binary.LittleEndian.Uint32(b[p:]))
		p += 4
		if p, err = polExpect(b, p, ';'); err != nil {
			return nil, err
		}
		if size < 0 || p+size > len(b) {
			return nil, errors.New("truncated Registry.pol")
		}
		e.Data = polDataString(e.Type, b[p:p+size])
		p += size
		if p, err = polExpect(b, p, ']'); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func polDataString(t uint32, d []byte) string {
	switch {
	case (t == regSZ || t == regExpandSZ) && len(d)%2 == 0:
		return strings.TrimRight(u16s(d, binary.LittleEndian), "\x00")
	case t == regDWord && len(d) == 4:
		return strconv.FormatUint(uint64(binary.LittleEndian.Uint32(d)), 10)
	case t == regQWord && len(d) == 8:
		return strconv.FormatUint(binary.LittleEndian.Uint64(d), 10)
	case t == regMultiSZ && len(d)%2 == 0:
		parts := strings.Split(u16s(d, binary.LittleEndian), "\x00")
		for len(parts) > 0 && parts[len(parts)-1] == "" {
			parts = parts[:len(parts)-1]
		}
		return strings.Join(parts, "\n")
	}
	return hex.EncodeToString(d)
}

func polDataBytes(t uint32, s string) ([]byte, error) {
	u16 := func(str string) []byte {
		var out []byte
		for _, v := range utf16.Encode([]rune(str)) {
			out = binary.LittleEndian.AppendUint16(out, v)
		}
		return out
	}
	switch t {
	case regSZ, regExpandSZ:
		return append(u16(s), 0, 0), nil
	case regDWord:
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
		if err != nil {
			return nil, errors.New("a DWORD value must be a number from 0 to 4294967295")
		}
		return binary.LittleEndian.AppendUint32(nil, uint32(n)), nil
	case regQWord:
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil, errors.New("a QWORD value must be a non-negative number")
		}
		return binary.LittleEndian.AppendUint64(nil, n), nil
	case regMultiSZ:
		var out []byte
		for _, line := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
			if line != "" {
				out = append(out, u16(line)...)
				out = append(out, 0, 0)
			}
		}
		return append(out, 0, 0), nil
	}
	h := strings.Map(func(r rune) rune {
		if r == ' ' || r == ':' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil, errors.New("binary data must be hexadecimal")
	}
	return b, nil
}

func buildPol(es []PolEntry) ([]byte, error) {
	out := []byte{'P', 'R', 'e', 'g', 1, 0, 0, 0}
	z := func(s string) []byte {
		var o []byte
		for _, v := range utf16.Encode([]rune(s)) {
			o = binary.LittleEndian.AppendUint16(o, v)
		}
		return append(o, 0, 0)
	}
	ch := func(c uint16) []byte { return binary.LittleEndian.AppendUint16(nil, c) }
	for _, e := range es {
		if e.Key == "" || len(e.Key) > 1024 || len(e.Value) > 1024 || strings.ContainsRune(e.Key+e.Value, 0) {
			return nil, errors.New("every entry needs a key; keys and value names must be shorter than 1024 characters")
		}
		d, err := polDataBytes(e.Type, e.Data)
		if err != nil {
			return nil, fmt.Errorf("%s\\%s: %w", e.Key, e.Value, err)
		}
		out = append(out, ch('[')...)
		out = append(out, z(e.Key)...)
		out = append(out, ch(';')...)
		out = append(out, z(e.Value)...)
		out = append(out, ch(';')...)
		out = binary.LittleEndian.AppendUint32(out, e.Type)
		out = append(out, ch(';')...)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(d)))
		out = append(out, ch(';')...)
		out = append(out, d...)
		out = append(out, ch(']')...)
	}
	return out, nil
}

func polScope(v string) (rel string, ext cseRef, machine bool, err error) {
	switch v {
	case "machine":
		return "Machine/Registry.pol", cseRegistryMach, true, nil
	case "user":
		return "User/Registry.pol", cseRegistryUser, false, nil
	}
	return "", cseRef{}, false, errors.New("scope must be machine or user")
}

func apiGPORegistry(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	_, dir, err := gpoFor(s, r.URL.Query().Get("guid"))
	if err != nil {
		return nil, err
	}
	rel, _, _, err := polScope(r.URL.Query().Get("scope"))
	if err != nil {
		return nil, err
	}
	full, exists, err := gpoPath(dir, rel)
	if err != nil {
		return nil, err
	}
	var b []byte
	if exists {
		if b, err = os.ReadFile(full); err != nil {
			return nil, err
		}
	}
	es, err := parsePol(b)
	if err != nil {
		return nil, err
	}
	return map[string]any{"entries": es, "etag": etagOf(b, exists), "exists": exists}, nil
}

func apiGPORegistrySave(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID    string     `json:"guid"`
		Scope   string     `json:"scope"`
		Entries []PolEntry `json:"entries"`
		ETag    string     `json:"etag"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, _, err := gpoFor(s, in.GUID)
	if err != nil {
		return nil, err
	}
	rel, ext, machine, err := polScope(in.Scope)
	if err != nil {
		return nil, err
	}
	data, err := buildPol(in.Entries)
	if err != nil {
		return nil, err
	}
	err = gpoCommit(s, guid, machine, !machine, []cseRef{ext}, func(dir string) (func() error, error) {
		full, exists, err := gpoPath(dir, rel)
		if err != nil {
			return nil, err
		}
		var cur []byte
		if exists {
			cur, _ = os.ReadFile(full)
		}
		if etagOf(cur, exists) != in.ETag {
			return nil, errors.New("Registry.pol was changed by someone else; reload it first")
		}
		return func() error {
			if err := mkdirAllLike(filepath.Dir(full)); err != nil {
				return err
			}
			return atomicWrite(full, data, 0o644, mustStat(filepath.Dir(full)))
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{"etag": etagOf(data, true)}, nil
}

// ---------- GptTmpl.inf (Security Settings) ----------

const secRel = "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"

type iniItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	NoEq  bool   `json:"noEq,omitempty"`
}
type iniSection struct {
	Name  string    `json:"name"`
	Items []iniItem `json:"items"`
}

func parseINI(txt string) []iniSection {
	secs := []iniSection{}
	for _, line := range strings.Split(strings.ReplaceAll(txt, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "\ufeff"))
		switch {
		case line == "" || strings.HasPrefix(line, ";"):
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			secs = append(secs, iniSection{Name: line[1 : len(line)-1], Items: []iniItem{}})
		default:
			if len(secs) == 0 {
				secs = append(secs, iniSection{Name: "", Items: []iniItem{}})
			}
			sec := &secs[len(secs)-1]
			if i := strings.IndexByte(line, '='); i >= 0 {
				sec.Items = append(sec.Items, iniItem{Key: strings.TrimSpace(line[:i]), Value: strings.TrimSpace(line[i+1:])})
			} else {
				sec.Items = append(sec.Items, iniItem{Key: line, NoEq: true})
			}
		}
	}
	return secs
}

func buildINI(secs []iniSection) (string, error) {
	hasU, hasV := false, false
	for _, s := range secs {
		hasU = hasU || strings.EqualFold(s.Name, "Unicode")
		hasV = hasV || strings.EqualFold(s.Name, "Version")
	}
	if !hasU {
		secs = append([]iniSection{{Name: "Unicode", Items: []iniItem{{Key: "Unicode", Value: "yes"}}}}, secs...)
	}
	if !hasV {
		secs = append(secs, iniSection{Name: "Version", Items: []iniItem{{Key: "signature", Value: `"$CHICAGO$"`}, {Key: "Revision", Value: "1"}}})
	}
	var sb strings.Builder
	for _, s := range secs {
		if s.Name == "" || strings.ContainsAny(s.Name, "[]\r\n\x00") {
			return "", errors.New("section names can't be empty or contain brackets or line breaks")
		}
		sb.WriteString("[" + s.Name + "]\r\n")
		for _, it := range s.Items {
			if it.Key == "" || strings.ContainsAny(it.Key+it.Value, "\r\n\x00") || (!it.NoEq && strings.Contains(it.Key, "=")) {
				return "", fmt.Errorf("[%s]: keys can't be empty or contain '=' or line breaks, values can't contain line breaks", s.Name)
			}
			if it.NoEq {
				sb.WriteString(it.Key + "\r\n")
			} else {
				sb.WriteString(it.Key + " = " + it.Value + "\r\n")
			}
		}
	}
	return sb.String(), nil
}

func apiGPOSecurity(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	_, dir, err := gpoFor(s, r.URL.Query().Get("guid"))
	if err != nil {
		return nil, err
	}
	full, exists, err := gpoPath(dir, secRel)
	if err != nil {
		return nil, err
	}
	var b []byte
	if exists {
		if b, err = os.ReadFile(full); err != nil {
			return nil, err
		}
	}
	txt, _ := decodeText(b)
	return map[string]any{"sections": parseINI(txt), "etag": etagOf(b, exists), "exists": exists}, nil
}

func apiGPOSecuritySave(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID     string       `json:"guid"`
		Sections []iniSection `json:"sections"`
		ETag     string       `json:"etag"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, _, err := gpoFor(s, in.GUID)
	if err != nil {
		return nil, err
	}
	txt, err := buildINI(in.Sections)
	if err != nil {
		return nil, err
	}
	data := encodeText(txt, "utf-16le")
	err = gpoCommit(s, guid, true, false, []cseRef{cseSecurity}, func(dir string) (func() error, error) {
		full, exists, err := gpoPath(dir, secRel)
		if err != nil {
			return nil, err
		}
		var cur []byte
		if exists {
			cur, _ = os.ReadFile(full)
		}
		if etagOf(cur, exists) != in.ETag {
			return nil, errors.New("GptTmpl.inf was changed by someone else; reload it first")
		}
		return func() error {
			if err := mkdirAllLike(filepath.Dir(full)); err != nil {
				return err
			}
			return atomicWrite(full, data, 0o644, mustStat(filepath.Dir(full)))
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{"etag": etagOf(data, true)}, nil
}

// ---------- plain files ----------

type gpoFileDTO struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size"`
	Mod  string `json:"modified"`
}

const maxFileRead = 4 << 20
const maxFileWrite = 700 << 10 // the request body limit is 1 MiB, and uploads travel as base64

func apiGPOFiles(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	_, dir, err := gpoFor(s, r.URL.Query().Get("guid"))
	if err != nil {
		return nil, err
	}
	full, exists, err := gpoPath(dir, r.URL.Query().Get("path"))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("no such folder")
	}
	es, err := os.ReadDir(full)
	if err != nil {
		return nil, err
	}
	out := []gpoFileDTO{}
	for _, e := range es {
		if strings.HasSuffix(e.Name(), ".goaduc-tmp") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		d := gpoFileDTO{Name: e.Name(), Dir: fi.IsDir(), Mod: fi.ModTime().UTC().Format(time.DateTime)}
		if !d.Dir {
			d.Size = fi.Size()
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return map[string]any{"files": out}, nil
}

func apiGPOFile(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	_, dir, err := gpoFor(s, r.URL.Query().Get("guid"))
	if err != nil {
		return nil, err
	}
	full, exists, err := gpoPath(dir, r.URL.Query().Get("path"))
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("no such file")
	}
	fi, err := os.Stat(full)
	if err != nil || fi.IsDir() {
		return nil, errors.New("not a file")
	}
	if fi.Size() > maxFileRead {
		return nil, errors.New("file is larger than 4 MiB")
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"size": len(b), "etag": etagOf(b, true)}
	if txt, enc, ok := isTextFile(b); ok {
		out["kind"], out["encoding"], out["text"] = "text", enc, txt
	} else {
		out["kind"], out["b64"] = "binary", base64.StdEncoding.EncodeToString(b)
	}
	return out, nil
}

func apiGPOFileSave(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID     string `json:"guid"`
		Path     string `json:"path"`
		Encoding string `json:"encoding"`
		Text     string `json:"text"`
		B64      string `json:"b64"`
		ETag     string `json:"etag"`
		Create   bool   `json:"create"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, _, err := gpoFor(s, in.GUID)
	if err != nil {
		return nil, err
	}
	machine, user, err := scopeOf(in.Path)
	if err != nil {
		return nil, err
	}
	var data []byte
	if in.B64 != "" {
		if data, err = base64.StdEncoding.DecodeString(in.B64); err != nil {
			return nil, errors.New("invalid upload")
		}
	} else {
		switch in.Encoding {
		case "", "utf-8", "utf-8-bom", "utf-16le", "utf-16be":
		default:
			return nil, errors.New("unknown text encoding")
		}
		data = encodeText(in.Text, in.Encoding)
	}
	if len(data) > maxFileWrite {
		return nil, errors.New("file is larger than 700 KiB")
	}
	err = gpoCommit(s, guid, machine, user, nil, func(dir string) (func() error, error) {
		full, exists, err := gpoPath(dir, in.Path)
		if err != nil {
			return nil, err
		}
		if exists {
			fi, err := os.Stat(full)
			if err != nil || fi.IsDir() {
				return nil, errors.New("that path is a folder")
			}
			if in.Create {
				return nil, errors.New("a file with that name already exists")
			}
			cur, _ := os.ReadFile(full)
			if etagOf(cur, true) != in.ETag {
				return nil, errors.New("the file was changed by someone else; reload it first")
			}
		} else if !in.Create {
			return nil, errors.New("no such file")
		}
		if st, err := os.Stat(filepath.Dir(full)); err != nil || !st.IsDir() {
			return nil, errors.New("the folder does not exist")
		}
		return func() error { return atomicWrite(full, data, 0o644, mustStat(filepath.Dir(full))) }, nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{"etag": etagOf(data, true)}, nil
}

func mustStat(p string) os.FileInfo { fi, _ := os.Stat(p); return fi }

func apiGPOFileDelete(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID string `json:"guid"`
		Path string `json:"path"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, _, err := gpoFor(s, in.GUID)
	if err != nil {
		return nil, err
	}
	rel, err := safeRel(in.Path)
	if err != nil {
		return nil, err
	}
	machine, user, err := scopeOf(rel)
	if err != nil {
		return nil, err
	}
	if !strings.Contains(rel, "/") {
		return nil, errors.New("the Machine and User folders can't be deleted")
	}
	err = gpoCommit(s, guid, machine, user, nil, func(dir string) (func() error, error) {
		full, exists, err := gpoPath(dir, rel)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, errors.New("no such file or folder")
		}
		return func() error { return os.RemoveAll(full) }, nil
	})
	return nil, err
}

func apiGPOMkdir(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID string `json:"guid"`
		Path string `json:"path"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, _, err := gpoFor(s, in.GUID)
	if err != nil {
		return nil, err
	}
	machine, user, err := scopeOf(in.Path)
	if err != nil {
		return nil, err
	}
	err = gpoCommit(s, guid, machine, user, nil, func(dir string) (func() error, error) {
		full, exists, err := gpoPath(dir, in.Path)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, errors.New("already exists")
		}
		return func() error { return mkdirAllLike(full) }, nil
	})
	return nil, err
}
