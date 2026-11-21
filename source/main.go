package main

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

//go:embed static
var staticFS embed.FS

var cfg Config

// ---------- sessions ----------

type Session struct {
	user, pass string
	base       string // default naming context
	config     string // configuration naming context
	root       string // forest root naming context
	schema     string
	ncs        []string
	mu         sync.Mutex
	conn       *Conn
	last       time.Time
}

var (
	sessMu   sync.Mutex
	sessions = map[string]*Session{}
)

const sessionIdle = 30 * time.Minute

func newToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Session) connect() error {
	c, err := Dial(&cfg)
	if err != nil {
		return err
	}
	if err := c.Bind(s.user, s.pass); err != nil {
		c.Close()
		return err
	}
	s.conn = c
	return nil
}

func isNetErr(err error) bool {
	var le *LDAPError
	if errors.As(err, &le) {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) || errors.Is(err, io.EOF) || strings.Contains(err.Error(), "EOF") ||
		strings.Contains(err.Error(), "broken pipe") || strings.Contains(err.Error(), "connection reset")
}

// With runs fn on the session's LDAP connection, reconnecting once on I/O errors.
func (s *Session) With(fn func(c *Conn) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = time.Now()
	for attempt := 0; attempt < 2; attempt++ {
		if s.conn == nil {
			if err := s.connect(); err != nil {
				return err
			}
		}
		err := fn(s.conn)
		if err != nil && isNetErr(err) {
			s.conn.nc.Close()
			s.conn = nil
			continue
		}
		return err
	}
	return errors.New("connection to directory server lost")
}

func janitor() {
	for range time.Tick(time.Minute) {
		sessMu.Lock()
		for k, s := range sessions {
			if time.Since(s.last) > sessionIdle {
				if s.conn != nil {
					s.conn.Close()
				}
				delete(sessions, k)
			}
		}
		sessMu.Unlock()
	}
}

// ---------- HTTP helpers ----------

type apiHandler func(w http.ResponseWriter, r *http.Request, s *Session) (any, error)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func errStatus(err error) int {
	var le *LDAPError
	if errors.As(err, &le) {
		switch le.Code {
		case 49:
			return 401
		case 50:
			return 403
		case 32:
			return 404
		case 68, 20:
			return 409
		}
		return 400
	}
	return 500
}

func auth(h apiHandler) http.HandlerFunc { return authOpt(h, true) }

// authStream is auth for a handler that reads a large raw body itself (the update upload): the body is not buffered
// here and the audit entry carries no detail.
func authStream(h apiHandler) http.HandlerFunc { return authOpt(h, false) }

func authOpt(h apiHandler, buffer bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Header.Get("X-Requested-With") != "aduc" {
			writeJSON(w, 403, map[string]string{"error": "missing X-Requested-With header"})
			return
		}
		ck, err := r.Cookie("aduc")
		if err != nil {
			writeJSON(w, 401, map[string]string{"error": "not logged in"})
			return
		}
		sessMu.Lock()
		s := sessions[ck.Value]
		sessMu.Unlock()
		if s == nil {
			writeJSON(w, 401, map[string]string{"error": "session expired"})
			return
		}
		var body []byte
		if r.Method != http.MethodGet && buffer {
			body, _ = io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		out, err := h(w, r, s)
		if r.Method != http.MethodGet {
			audit(s.user, r.URL.Path, body, err)
		}
		if err != nil {
			log.Printf("%s %s (%s): %v", r.Method, r.URL.Path, s.user, err)
			writeJSON(w, errStatus(err), map[string]string{"error": err.Error()})
			return
		}
		if out == nil {
			out = map[string]bool{"ok": true}
		}
		writeJSON(w, 200, out)
	}
}

func decode(r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	return json.NewDecoder(r.Body).Decode(v)
}

// ---------- DN helpers ----------

func escapeRDN(s string) string {
	var sb strings.Builder
	for i, r := range s {
		switch {
		case strings.ContainsRune(",+\"\\<>;=", r):
			sb.WriteByte('\\')
			sb.WriteRune(r)
		case r == 0:
			sb.WriteString("\\00")
		case (i == 0 && (r == ' ' || r == '#')):
			sb.WriteByte('\\')
			sb.WriteRune(r)
		default:
			sb.WriteRune(r)
		}
	}
	out := sb.String()
	if strings.HasSuffix(out, " ") && !strings.HasSuffix(out, "\\ ") {
		out = out[:len(out)-1] + "\\ "
	}
	return out
}

func splitDN(dn string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(dn); i++ {
		if dn[i] == '\\' {
			i++
		} else if dn[i] == ',' {
			parts = append(parts, dn[start:i])
			start = i + 1
		}
	}
	return append(parts, dn[start:])
}

func parentDN(dn string) string {
	p := splitDN(dn)
	if len(p) < 2 {
		return ""
	}
	return strings.Join(p[1:], ",")
}

func firstRDN(dn string) string { return splitDN(dn)[0] }

func realmFromBase(base string) string {
	var parts []string
	for _, p := range splitDN(base) {
		if len(p) > 3 && strings.EqualFold(p[:3], "dc=") {
			parts = append(parts, p[3:])
		}
	}
	return strings.Join(parts, ".")
}

func within(dn, base string) bool {
	d, b := strings.ToLower(dn), strings.ToLower(base)
	return d == b || strings.HasSuffix(d, ","+b)
}

// ---------- object helpers ----------

func has(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func kindOf(oc []string) string {
	switch {
	case has(oc, "computer"):
		return "computer"
	case has(oc, "user") || has(oc, "inetOrgPerson"):
		return "user"
	case has(oc, "group"):
		return "group"
	case has(oc, "organizationalUnit"):
		return "ou"
	case has(oc, "domainDNS"):
		return "domain"
	case has(oc, "builtinDomain"):
		return "builtin"
	case has(oc, "site"):
		return "site"
	case has(oc, "subnet"):
		return "subnet"
	case has(oc, "siteLink"):
		return "sitelink"
	case has(oc, "serversContainer"):
		return "servers"
	case has(oc, "server"):
		return "server"
	case has(oc, "nTDSDSA"):
		return "ntds"
	case has(oc, "nTDSConnection"):
		return "connection"
	case has(oc, "nTDSSiteSettings"):
		return "sitesettings"
	case has(oc, "interSiteTransport"):
		return "transport"
	case has(oc, "sitesContainer") || has(oc, "subnetContainer") || has(oc, "interSiteTransportContainer") || has(oc, "configuration"):
		return "container"
	case has(oc, "container") || has(oc, "lostAndFound") || has(oc, "msDS-QuotaContainer"):
		return "container"
	case has(oc, "contact"):
		return "contact"
	case has(oc, "foreignSecurityPrincipal"):
		return "fsp"
	}
	return "other"
}

func isContainerKind(k string) bool {
	switch k {
	case "ou", "container", "domain", "builtin", "site", "servers", "server", "ntds", "transport":
		return true
	}
	return false
}

type Item struct {
	DN       string `json:"dn"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Desc     string `json:"description"`
	Sam      string `json:"sam,omitempty"`
	UPN      string `json:"upn,omitempty"`
	Mail     string `json:"mail,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	// Sites and Services details (site, location, cost, interval, sites, from, dns)
	Extra map[string]string `json:"extra,omitempty"`
	Class string            `json:"class,omitempty"` // most specific objectClass
	Cont  bool              `json:"cont,omitempty"`  // can hold other objects: shown as a node in the LDAP Browser tree
}

// containerClasses are the classes that hold other objects. Anything derived from "container" counts too (AD lists the
// whole class chain in objectClass), so e.g. nTDSService and msDS-QuotaContainer are covered either way.
var containerClasses = map[string]bool{"container": true, "organizationalunit": true, "domain": true, "domaindns": true,
	"builtindomain": true, "dnszone": true, "configuration": true, "crossrefcontainer": true, "site": true, "sitescontainer": true,
	"serverscontainer": true, "server": true, "ntdsservice": true, "ntdssitesettings": true, "intersitetransport": true,
	"intersitetransportcontainer": true, "lostandfound": true, "dmd": true}

func isContainerClass(oc []string) bool {
	for _, c := range oc {
		if containerClasses[strings.ToLower(c)] {
			return true
		}
	}
	return false
}

var listAttrs = []string{"name", "objectClass", "description", "userAccountControl", "sAMAccountName", "userPrincipalName", "mail", "displayName",
	"siteObject", "location", "cost", "replInterval", "siteList", "fromServer", "dNSHostName", "enabledConnection", "options"}

func toItem(e *Entry) Item {
	it := Item{DN: e.DN, Type: kindOf(e.Strs("objectClass")), Desc: strings.Join(e.Strs("description"), "; "),
		Sam: e.Get("sAMAccountName"), UPN: e.Get("userPrincipalName"), Mail: e.Get("mail")}
	it.Name = e.Get("name")
	if it.Name == "" {
		rdn := firstRDN(e.DN)
		it.Name = rdn[strings.IndexByte(rdn+"=", '=')+1:]
	}
	if oc := e.Strs("objectClass"); len(oc) > 0 {
		it.Class = oc[len(oc)-1]
		it.Cont = isContainerClass(oc)
	}
	ex := map[string]string{}
	if v := e.Get("siteObject"); v != "" {
		ex["site"] = dnLabel(v, 0)
	}
	for _, kv := range [][2]string{{"location", "location"}, {"cost", "cost"}, {"replInterval", "interval"}, {"dNSHostName", "dns"}, {"enabledConnection", "enabled"}} {
		if v := e.Get(kv[0]); v != "" {
			ex[kv[1]] = v
		}
	}
	if sl := e.Strs("siteList"); len(sl) > 0 {
		var n []string
		for _, d := range sl {
			n = append(n, dnLabel(d, 0))
		}
		sort.Strings(n)
		ex["sites"] = strings.Join(n, ", ")
	}
	if v := e.Get("fromServer"); v != "" {
		ex["from"] = dnLabel(v, 1)
	}
	if len(ex) > 0 {
		it.Extra = ex
	}
	if uac, err := strconv.Atoi(e.Get("userAccountControl")); err == nil && uac&2 != 0 {
		it.Disabled = true
	}
	return it
}

// dnLabel returns the value of the idx-th RDN of a DN.
func dnLabel(dn string, idx int) string {
	p := splitDN(dn)
	if idx >= len(p) {
		return dn
	}
	r := p[idx]
	return strings.ReplaceAll(r[strings.IndexByte(r+"=", '=')+1:], "\\", "")
}

func sortItems(items []Item) {
	rank := func(t string) int {
		if isContainerKind(t) {
			return 0
		}
		return 1
	}
	sort.SliceStable(items, func(i, j int) bool {
		if rank(items[i].Type) != rank(items[j].Type) {
			return rank(items[i].Type) < rank(items[j].Type)
		}
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
}

func sidString(b []byte) string {
	if len(b) < 8 {
		return hex.EncodeToString(b)
	}
	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}
	s := fmt.Sprintf("S-%d-%d", b[0], auth)
	n := int(b[1])
	for i := 0; i < n && 8+4*i+4 <= len(b); i++ {
		o := 8 + 4*i
		s += fmt.Sprintf("-%d", uint32(b[o])|uint32(b[o+1])<<8|uint32(b[o+2])<<16|uint32(b[o+3])<<24)
	}
	return s
}

func guidString(b []byte) string {
	if len(b) != 16 {
		return hex.EncodeToString(b)
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%x",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10:])
}

var timeAttrs = map[string]bool{"pwdlastset": true, "lastlogon": true, "lastlogontimestamp": true,
	"accountexpires": true, "lockouttime": true, "badpasswordtime": true}

func fileTime(v string) string {
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return ""
	}
	if n == 0x7FFFFFFFFFFFFFFF {
		return "never"
	}
	t := time.Unix(n/10000000-11644473600, 0).UTC()
	return t.Format("2006-01-02 15:04:05 UTC")
}

func printable(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}

func utf16Pwd(pw string) []byte {
	u := utf16.Encode([]rune("\"" + pw + "\""))
	b := make([]byte, 0, len(u)*2)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}

func sv(s string) [][]byte { return [][]byte{[]byte(s)} }

func svs(ss []string) [][]byte {
	var out [][]byte
	for _, s := range ss {
		out = append(out, []byte(s))
	}
	return out
}

func requireIn(s *Session, dn string) error {
	ok := dn != "" && (within(dn, s.base) || within(dn, s.config) || within(dn, s.root))
	for _, nc := range s.ncs {
		ok = ok || (dn != "" && within(dn, nc))
	}
	if !ok {
		return fmt.Errorf("DN %q is outside the domain", dn)
	}
	return nil
}

func isProtectedDN(s *Session, dn string) bool {
	if strings.EqualFold(dn, s.base) {
		return true
	}
	sites := "CN=Sites," + s.config
	for _, p := range []string{s.config, sites, "CN=Subnets," + sites, "CN=Inter-Site Transports," + sites,
		"CN=IP,CN=Inter-Site Transports," + sites, "CN=SMTP,CN=Inter-Site Transports," + sites} {
		if strings.EqualFold(dn, p) {
			return true
		}
	}
	return false
}

// ---------- handlers ----------

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Requested-With") != "aduc" {
		writeJSON(w, 403, map[string]string{"error": "bad request"})
		return
	}
	var in struct{ Username, Password string }
	if err := decode(r, &in); err != nil || in.Username == "" {
		writeJSON(w, 400, map[string]string{"error": "username and password required"})
		return
	}
	open := func(user string) (*Session, error) {
		s := &Session{user: user, pass: in.Password, last: time.Now()}
		err := s.With(func(c *Conn) error {
			es, _, err := c.Search("", ScopeBase, "(objectClass=*)", []string{"defaultNamingContext", "configurationNamingContext", "rootDomainNamingContext", "schemaNamingContext", "namingContexts"}, 1)
			if err != nil {
				return err
			}
			if len(es) > 0 {
				s.base = es[0].Get("defaultNamingContext")
				s.config = es[0].Get("configurationNamingContext")
				s.root = es[0].Get("rootDomainNamingContext")
				s.schema = es[0].Get("schemaNamingContext")
				s.ncs = es[0].Strs("namingContexts")
			}
			if s.root == "" {
				s.root = s.base
			}
			if s.config == "" && s.base != "" {
				s.config = "CN=Configuration," + s.base
			}
			return nil
		})
		if err == nil && s.base == "" {
			err = errors.New("could not determine the domain naming context")
		}
		return s, err
	}
	s, err := open(in.Username)
	// A bare logon name (sAMAccountName) is tried as typed first; if the server refuses it,
	// retry as name@realm, with the realm read from the server's anonymous RootDSE.
	var le *LDAPError
	if err != nil && errors.As(err, &le) && le.Code == 49 && !strings.ContainsAny(in.Username, "@\\=") {
		if realm := rootDSERealm(); realm != "" {
			if s2, err2 := open(in.Username + "@" + realm); err2 == nil {
				s, err = s2, nil
			}
		}
	}
	audit(in.Username, "/api/login", nil, err)
	if err != nil {
		time.Sleep(500 * time.Millisecond)
		msg := err.Error()
		writeJSON(w, errStatus(err), map[string]string{"error": msg})
		return
	}
	tok := newToken()
	sessMu.Lock()
	sessions[tok] = s
	sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "aduc", Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: r.TLS != nil, MaxAge: 0})
	writeJSON(w, 200, map[string]any{"user": s.user, "base": s.base, "config": s.config, "root": s.root, "schema": s.schema, "ncs": s.ncs, "realm": realmFromBase(s.base)})
}

// rootDSERealm reads the domain name from the server's RootDSE over an unauthenticated connection ("" if unavailable).
func rootDSERealm() string {
	c, err := Dial(&cfg)
	if err != nil {
		return ""
	}
	defer c.Close()
	e, err := c.Read("", []string{"defaultNamingContext"})
	if err != nil {
		return ""
	}
	return realmFromBase(e.Get("defaultNamingContext"))
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie("aduc"); err == nil {
		sessMu.Lock()
		if s := sessions[ck.Value]; s != nil && s.conn != nil {
			s.conn.Close()
		}
		delete(sessions, ck.Value)
		sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "aduc", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func apiInfo(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	return map[string]any{"user": s.user, "base": s.base, "config": s.config, "root": s.root, "schema": s.schema, "ncs": s.ncs, "realm": realmFromBase(s.base), "tls": s.conn != nil && s.conn.IsTLS}, nil
}

func apiChildren(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	dn := r.URL.Query().Get("dn")
	if dn == "" {
		dn = s.base
	}
	if err := requireIn(s, dn); err != nil {
		return nil, err
	}
	var es []*Entry
	trunc := false
	err := s.With(func(c *Conn) error {
		var err error
		es, trunc, err = c.Search(dn, ScopeOne, "(objectClass=*)", listAttrs, 5000)
		return err
	})
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(es))
	for _, e := range es {
		items = append(items, toItem(e))
	}
	sortItems(items)
	return map[string]any{"items": items, "truncated": trunc}, nil
}

func apiSearch(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	typ := r.URL.Query().Get("type")
	base := r.URL.Query().Get("base")
	if base == "" {
		base = s.base
	}
	if err := requireIn(s, base); err != nil {
		return nil, err
	}
	var filter string
	if strings.HasPrefix(q, "(") {
		filter = q
	} else {
		var kind string
		switch typ {
		case "user":
			kind = "(&(objectClass=user)(!(objectClass=computer)))"
		case "computer":
			kind = "(objectClass=computer)"
		case "group":
			kind = "(objectClass=group)"
		case "ou":
			kind = "(objectClass=organizationalUnit)"
		case "any":
			kind = "(objectClass=*)"
		case "site":
			kind = "(objectClass=site)"
		case "ntds":
			kind = "(objectClass=nTDSDSA)"
		case "disabled":
			kind = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))"
		default:
			kind = "(|(objectClass=user)(objectClass=group)(objectClass=organizationalUnit)(objectClass=contact)(objectClass=container))"
		}
		if q == "" {
			filter = kind
		} else {
			e := EscapeFilter(q)
			var f strings.Builder
			f.WriteString("(&" + kind + "(|")
			for _, a := range []string{"name", "sAMAccountName", "displayName", "userPrincipalName", "mail", "description", "givenName", "sn"} {
				f.WriteString("(" + a + "=*" + e + "*)")
			}
			f.WriteString("))")
			filter = f.String()
		}
	}
	var es []*Entry
	trunc := false
	err := s.With(func(c *Conn) error {
		var err error
		es, trunc, err = c.Search(base, ScopeSub, filter, listAttrs, 500)
		return err
	})
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(es))
	for _, e := range es {
		items = append(items, toItem(e))
	}
	sortItems(items)
	return map[string]any{"items": items, "truncated": trunc}, nil
}

func apiGetObject(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	dn := r.URL.Query().Get("dn")
	if err := requireIn(s, dn); err != nil {
		return nil, err
	}
	var e *Entry
	err := s.With(func(c *Conn) error {
		var err error
		e, err = c.Read(dn, []string{"*", "msDS-User-Account-Control-Computed"})
		return err
	})
	if err != nil {
		return nil, err
	}
	attrs := map[string][]string{}
	var binary []string
	times := map[string]string{}
	for k, vs := range e.Attrs {
		var out []string
		isBin := false
		for _, v := range vs {
			switch {
			case strings.EqualFold(k, "objectSid"):
				out = append(out, sidString(v))
				isBin = true
			case strings.EqualFold(k, "objectGUID"):
				out = append(out, guidString(v))
				isBin = true
			case strings.EqualFold(k, "logonHours"):
				out = append(out, hex.EncodeToString(v))
				isBin = true
			case printable(v):
				out = append(out, string(v))
			default:
				out = append(out, hex.EncodeToString(v))
				isBin = true
			}
		}
		if isBin {
			binary = append(binary, k)
		}
		if timeAttrs[strings.ToLower(k)] && len(out) == 1 {
			if t := fileTime(out[0]); t != "" {
				times[k] = t
			}
		}
		attrs[k] = out
	}
	return map[string]any{"dn": e.DN, "type": kindOf(e.Strs("objectClass")), "attrs": attrs, "binary": binary, "times": times}, nil
}

func apiModify(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		DN  string              `json:"dn"`
		Set map[string][]string `json:"set"` // replace (empty list deletes attribute)
		Bin map[string][]string `json:"bin"` // base64 values for a few binary attributes
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.DN); err != nil {
		return nil, err
	}
	var mods []Mod
	for k, v := range in.Set {
		switch strings.ToLower(k) {
		case "unicodepwd", "userpassword", "dbcspwd", "objectguid", "objectsid", "distinguishedname", "objectclass", "name":
			return nil, fmt.Errorf("attribute %s cannot be edited here", k)
		}
		var clean []string
		for _, x := range v {
			if x != "" {
				clean = append(clean, x)
			}
		}
		mods = append(mods, Mod{Op: 2, Attr: k, Vals: svs(clean)})
	}
	for k, v := range in.Bin {
		if !strings.EqualFold(k, "logonHours") {
			return nil, fmt.Errorf("attribute %s cannot be set as binary", k)
		}
		var vals [][]byte
		for _, x := range v {
			b, err := base64.StdEncoding.DecodeString(x)
			if err != nil || len(b) != 21 {
				return nil, errors.New("logonHours must be exactly 21 bytes")
			}
			vals = append(vals, b)
		}
		mods = append(mods, Mod{Op: 2, Attr: k, Vals: vals})
	}
	if len(mods) == 0 {
		return nil, errors.New("nothing to change")
	}
	return nil, s.With(func(c *Conn) error { return c.Modify(in.DN, mods) })
}

func apiDelete(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		DN        string `json:"dn"`
		Recursive bool   `json:"recursive"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.DN); err != nil {
		return nil, err
	}
	if isProtectedDN(s, in.DN) {
		return nil, errors.New("this built-in container cannot be deleted")
	}
	return nil, s.With(func(c *Conn) error { return c.Delete(in.DN, in.Recursive) })
}

func apiMove(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct{ DN, NewParent string }
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.DN); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.NewParent); err != nil {
		return nil, err
	}
	if within(in.DN, s.config) != within(in.NewParent, s.config) {
		return nil, errors.New("cannot move objects between the domain and Configuration partitions")
	}
	if isProtectedDN(s, in.DN) {
		return nil, errors.New("this container cannot be moved")
	}
	if within(in.NewParent, in.DN) {
		return nil, errors.New("cannot move an object into itself")
	}
	return map[string]string{"dn": firstRDN(in.DN) + "," + in.NewParent},
		s.With(func(c *Conn) error { return c.ModifyDN(in.DN, firstRDN(in.DN), in.NewParent) })
}

func apiRename(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct{ DN, Name string }
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.DN); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || isProtectedDN(s, in.DN) {
		return nil, errors.New("invalid name")
	}
	rdn := firstRDN(in.DN)
	typ := rdn[:strings.IndexByte(rdn, '=')]
	newRDN := typ + "=" + escapeRDN(in.Name)
	return map[string]string{"dn": newRDN + "," + parentDN(in.DN)},
		s.With(func(c *Conn) error { return c.ModifyDN(in.DN, newRDN, "") })
}

func setPassword(c *Conn, dn, pw string, mustChange bool) error {
	mods := []Mod{{Op: 2, Attr: "unicodePwd", Vals: [][]byte{utf16Pwd(pw)}}}
	if err := c.Modify(dn, mods); err != nil {
		var le *LDAPError
		if errors.As(err, &le) && (le.Code == 53 || le.Code == 8) && !c.IsTLS {
			return errors.New("the directory server refuses password changes on an unencrypted connection; use an ldaps:// server URL or -starttls")
		}
		return err
	}
	if mustChange {
		return c.Modify(dn, []Mod{{Op: 2, Attr: "pwdLastSet", Vals: sv("0")}})
	}
	return nil
}

func apiPassword(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		DN         string `json:"dn"`
		Password   string `json:"password"`
		MustChange bool   `json:"mustChange"`
		Unlock     bool   `json:"unlock"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.DN); err != nil {
		return nil, err
	}
	if in.Password == "" {
		return nil, errors.New("password required")
	}
	return nil, s.With(func(c *Conn) error {
		if err := setPassword(c, in.DN, in.Password, in.MustChange); err != nil {
			return err
		}
		if in.Unlock {
			return c.Modify(in.DN, []Mod{{Op: 2, Attr: "lockoutTime", Vals: sv("0")}})
		}
		return nil
	})
}

func apiUAC(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		DN    string `json:"dn"`
		Set   int    `json:"set"`
		Clear int    `json:"clear"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.DN); err != nil {
		return nil, err
	}
	return nil, s.With(func(c *Conn) error {
		e, err := c.Read(in.DN, []string{"userAccountControl"})
		if err != nil {
			return err
		}
		cur, err := strconv.Atoi(e.Get("userAccountControl"))
		if err != nil {
			return errors.New("object has no userAccountControl")
		}
		n := (cur | in.Set) &^ in.Clear
		if n == cur {
			return nil
		}
		return c.Modify(in.DN, []Mod{{Op: 2, Attr: "userAccountControl", Vals: sv(strconv.Itoa(n))}})
	})
}

func apiUnlock(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct{ DN string }
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.DN); err != nil {
		return nil, err
	}
	return nil, s.With(func(c *Conn) error {
		return c.Modify(in.DN, []Mod{{Op: 2, Attr: "lockoutTime", Vals: sv("0")}})
	})
}

func apiMembers(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		Group  string   `json:"group"`
		Add    []string `json:"add"`
		Remove []string `json:"remove"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.Group); err != nil {
		return nil, err
	}
	var errs []string
	err := s.With(func(c *Conn) error {
		// one at a time so a single failure (e.g. already a member) doesn't abort the rest
		for _, m := range in.Add {
			if err := c.Modify(in.Group, []Mod{{Op: 0, Attr: "member", Vals: sv(m)}}); err != nil {
				errs = append(errs, m+": "+err.Error())
			}
		}
		for _, m := range in.Remove {
			if err := c.Modify(in.Group, []Mod{{Op: 1, Attr: "member", Vals: sv(m)}}); err != nil {
				errs = append(errs, m+": "+err.Error())
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(errs) > 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	return nil, nil
}

// ---- creation ----

func apiCreate(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		Kind        string `json:"kind"`
		Parent      string `json:"parent"`
		Name        string `json:"name"` // cn / ou / computer name
		Description string `json:"description"`
		// users
		First, Last, Display string
		Sam, UPN             string
		Password             string
		MustChange           bool `json:"mustChange"`
		NeverExpires         bool `json:"neverExpires"`
		Disabled             bool `json:"disabled"`
		// groups
		Scope     string `json:"scope"` // global|domainlocal|universal
		GroupType string `json:"groupType"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.Parent); err != nil {
		return nil, err
	}
	if within(in.Parent, s.config) {
		return nil, errors.New("objects of this kind cannot be created in the Configuration partition")
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	var dn string
	var attrs []Mod
	add := func(a string, v string) {
		if v != "" {
			attrs = append(attrs, Mod{Attr: a, Vals: sv(v)})
		}
	}
	switch in.Kind {
	case "ou":
		dn = "OU=" + escapeRDN(in.Name) + "," + in.Parent
		attrs = append(attrs, Mod{Attr: "objectClass", Vals: svs([]string{"top", "organizationalUnit"})})
		add("ou", in.Name)
		add("description", in.Description)
	case "group":
		sam := in.Sam
		if sam == "" {
			sam = in.Name
		}
		gt := int32(2)
		switch in.Scope {
		case "domainlocal":
			gt = 4
		case "universal":
			gt = 8
		}
		if in.GroupType != "distribution" {
			gt |= -2147483648
		}
		dn = "CN=" + escapeRDN(in.Name) + "," + in.Parent
		attrs = append(attrs, Mod{Attr: "objectClass", Vals: svs([]string{"top", "group"})})
		add("cn", in.Name)
		add("sAMAccountName", sam)
		add("groupType", strconv.Itoa(int(gt)))
		add("description", in.Description)
	case "computer":
		sam := strings.ToUpper(in.Name)
		if !strings.HasSuffix(sam, "$") {
			sam += "$"
		}
		dn = "CN=" + escapeRDN(in.Name) + "," + in.Parent
		attrs = append(attrs, Mod{Attr: "objectClass", Vals: svs([]string{"top", "person", "organizationalPerson", "user", "computer"})})
		add("cn", in.Name)
		add("sAMAccountName", sam)
		add("userAccountControl", "4096")
		add("description", in.Description)
	case "user":
		if in.Sam == "" {
			return nil, errors.New("logon name (sAMAccountName) is required")
		}
		if in.Password == "" {
			return nil, errors.New("password is required")
		}
		upn := in.UPN
		if upn == "" {
			upn = in.Sam + "@" + realmFromBase(s.base)
		}
		disp := in.Display
		if disp == "" {
			disp = strings.TrimSpace(in.First + " " + in.Last)
		}
		dn = "CN=" + escapeRDN(in.Name) + "," + in.Parent
		attrs = append(attrs, Mod{Attr: "objectClass", Vals: svs([]string{"top", "person", "organizationalPerson", "user"})})
		add("cn", in.Name)
		add("sAMAccountName", in.Sam)
		add("userPrincipalName", upn)
		add("givenName", in.First)
		add("sn", in.Last)
		add("displayName", disp)
		add("description", in.Description)
		add("userAccountControl", "514") // created disabled until the password is set
	default:
		return nil, errors.New("unknown object kind")
	}
	err := s.With(func(c *Conn) error {
		if err := c.Add(dn, attrs); err != nil {
			return err
		}
		if in.Kind != "user" {
			return nil
		}
		uac := 512
		if in.NeverExpires {
			uac |= 0x10000
		}
		if in.Disabled {
			uac |= 2
		}
		fail := func(err error) error {
			c.Delete(dn, false) // roll back the half-created account
			return err
		}
		if err := setPassword(c, dn, in.Password, false); err != nil {
			return fail(err)
		}
		mods := []Mod{{Op: 2, Attr: "userAccountControl", Vals: sv(strconv.Itoa(uac))}}
		if in.MustChange && !in.NeverExpires {
			mods = append(mods, Mod{Op: 2, Attr: "pwdLastSet", Vals: sv("0")})
		}
		if err := c.Modify(dn, mods); err != nil {
			return fail(err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{"dn": dn}, nil
}

//go:embed VERSION
var versionFile string

func version() string { return strings.TrimSpace(versionFile) }

func main() {
	listen := flag.String("listen", envOr("ADUC_LISTEN", ""), "listen address (default :8443 for HTTPS, 127.0.0.1:8080 with -http)")
	flag.StringVar(&cfg.URL, "server", envOr("ADUC_SERVER", "ldaps://localhost:636"), "LDAP server URL (ldaps://dc.example.com:636 or ldap://...)")
	flag.BoolVar(&cfg.StartTLS, "starttls", os.Getenv("ADUC_STARTTLS") == "1", "use StartTLS on ldap:// connections")
	flag.BoolVar(&cfg.Insecure, "insecure", os.Getenv("ADUC_INSECURE") == "1", "skip LDAP TLS certificate verification (Samba self-signed certs)")
	flag.StringVar(&cfg.CAFile, "ca", os.Getenv("ADUC_CA"), "PEM CA file to trust for LDAP (e.g. /var/lib/samba/private/tls/ca.pem)")
	dataDir := flag.String("data-dir", envOr("ADUC_DATA_DIR", defaultDataDir()), "state directory (holds the auto-generated web certificate)")
	certFile := flag.String("tls-cert", os.Getenv("ADUC_TLS_CERT"), "web UI certificate (default: self-signed, auto-generated in -data-dir)")
	keyFile := flag.String("tls-key", os.Getenv("ADUC_TLS_KEY"), "key for -tls-cert")
	flag.StringVar(&sysvolRoot, "sysvol", os.Getenv("ADUC_SYSVOL"), "SYSVOL directory on this host, for editing Group Policy settings (default /var/lib/samba/sysvol if present)")
	flag.StringVar(&samDB, "sam-db", envOr("ADUC_SAMDB", samDB), "Samba sam.ldb, used only to enable the Recycle Bin when Samba refuses it over LDAP (needs root and ldbmodify)")
	plain := flag.Bool("http", os.Getenv("ADUC_HTTP") == "1", "serve plain HTTP instead of HTTPS (not recommended)")
	flag.StringVar(&updateRepo, "update-repo", envOr("ADUC_UPDATE_REPO", defaultUpdateRepo), "GitHub owner/repo the Update page fetches releases from")
	flag.BoolVar(&updateDisabled, "no-update", os.Getenv("ADUC_NO_UPDATE") == "1", "turn off the Update page (software updates from the web UI)")
	auditPath := flag.String("audit-log", os.Getenv("ADUC_AUDIT_LOG"), "append JSON-lines audit log of changes to this file")
	showVer := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVer {
		fmt.Println("goaduc v" + version())
		return
	}
	openAudit(*auditPath)
	if !repoRe.MatchString(updateRepo) {
		log.Fatalf("-update-repo %q: want owner/repo", updateRepo)
	}
	initUpdate(*dataDir)
	initDNSBin(*dataDir)
	initPeers(*dataDir)
	if sysvolRoot == "" {
		if st, err := os.Stat("/var/lib/samba/sysvol"); err == nil && st.IsDir() {
			sysvolRoot = "/var/lib/samba/sysvol"
		}
	}
	if sysvolRoot != "" && os.Geteuid() != 0 {
		log.Printf("note: not running as root, so Group Policy settings in %s may not be writable", sysvolRoot)
	}

	mux := buildMux()
	go janitor()
	h := securityHeaders(mux)

	if *plain {
		webCert.plain = true
		if *listen == "" {
			*listen = "127.0.0.1:8080"
		}
		log.Printf("goaduc v%s: listening on http://%s, directory %s", version(), *listen, cfg.URL)
		if host, _, _ := net.SplitHostPort(*listen); host != "127.0.0.1" && host != "localhost" && host != "::1" {
			log.Printf("WARNING: serving over plain HTTP on a non-loopback address; credentials will cross the network unencrypted.")
		}
		log.Fatal(http.ListenAndServe(*listen, h))
	}

	if *listen == "" {
		*listen = ":8443"
	}
	if _, port, err := net.SplitHostPort(*listen); err == nil && port != "" {
		webPort = port // the other DCs' goaduc are expected on the same port
	}
	auto := *certFile == "" && *keyFile == ""
	if !auto && (*certFile == "" || *keyFile == "") {
		log.Fatal("-tls-cert and -tls-key must be given together")
	}
	if auto {
		if err := webCert.initAuto(filepath.Join(*dataDir, "tls")); err != nil {
			log.Fatalf("certificate: %v", err)
		}
		*certFile = filepath.Join(*dataDir, "tls", "server.crt")
		if webCert.custom {
			*certFile = filepath.Join(*dataDir, "tls", "custom.crt")
		}
	} else if err := webCert.initFiles(*certFile, *keyFile); err != nil {
		log.Fatalf("certificate: %v", err)
	}
	if fp, err := certFingerprint(*certFile); err == nil {
		log.Printf("web certificate %s  SHA-256 %s", *certFile, fp)
	}
	log.Printf("goaduc v%s: listening on https://%s, directory %s", version(), *listen, cfg.URL)
	srv := &http.Server{Addr: *listen, Handler: h, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: webCert.getCertificate}}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// buildMux wires up all HTTP routes.
func buildMux() *http.ServeMux {
	sub, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(sub)))
	registerUpdate(mux)
	registerWebCert(mux)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/logout", handleLogout)
	mux.HandleFunc("/api/info", auth(apiInfo))
	mux.HandleFunc("/api/children", auth(apiChildren))
	mux.HandleFunc("/api/search", auth(apiSearch))
	mux.HandleFunc("/api/object", auth(func(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
		switch r.Method {
		case http.MethodGet:
			return apiGetObject(w, r, s)
		case http.MethodPut:
			return apiModify(w, r, s)
		}
		return nil, errors.New("method not allowed")
	}))
	mux.HandleFunc("/api/create", auth(apiCreate))
	mux.HandleFunc("/api/sites/create", auth(apiSitesCreate))
	mux.HandleFunc("/api/delete", auth(apiDelete))
	mux.HandleFunc("/api/move", auth(apiMove))
	mux.HandleFunc("/api/rename", auth(apiRename))
	mux.HandleFunc("/api/password", auth(apiPassword))
	mux.HandleFunc("/api/uac", auth(apiUAC))
	mux.HandleFunc("/api/unlock", auth(apiUnlock))
	mux.HandleFunc("/api/members", auth(apiMembers))

	registerTools(mux)
	return mux
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
