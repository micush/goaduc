package main

// Domain info, password policy, fine-grained password policies (PSOs),
// reports, recycle bin and the audit log.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func registerTools(mux *http.ServeMux) {
	mux.HandleFunc("/api/dns/zones", auth(apiDNSZones))
	mux.HandleFunc("/api/dns/records", auth(apiDNSRecords))
	mux.HandleFunc("/api/dns/save", auth(apiDNSSave))
	mux.HandleFunc("/api/dns/delete", auth(apiDNSDelete))
	mux.HandleFunc("/api/domaininfo", auth(apiDomainInfo))
	mux.HandleFunc("/api/policy", auth(apiPolicy))
	mux.HandleFunc("/api/upnsuffixes", auth(apiUPNSuffixes))
	mux.HandleFunc("/api/pso", auth(apiPSOList))
	mux.HandleFunc("/api/pso/save", auth(apiPSOSave))
	mux.HandleFunc("/api/report", auth(apiReport))
	mux.HandleFunc("/api/deleted", auth(apiDeleted))
	mux.HandleFunc("/api/deleted/restore", auth(apiRestore))
	mux.HandleFunc("/api/deleted/purge", auth(apiPurge))
	mux.HandleFunc("/api/deleted/dns/restore", auth(apiDNSRestore))
	mux.HandleFunc("/api/recyclebin/enable", auth(apiRecycleEnable))
	mux.HandleFunc("/api/recyclebin", auth(apiRecycleStatus))
	registerGPO(mux)
	mux.HandleFunc("/api/audit", auth(apiAudit))
}

// ---------- audit log ----------

type AuditEntry struct {
	Time   string `json:"time"`
	User   string `json:"user"`
	Action string `json:"action"`
	Detail string `json:"detail"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

var (
	auditMu   sync.Mutex
	auditRing []AuditEntry
	auditFile *os.File
)

func openAudit(path string) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatalf("cannot open audit log: %v", err)
	}
	auditFile = f
}

func redact(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			lk := strings.ToLower(k)
			if strings.Contains(lk, "pass") || lk == "pw" || lk == "key" || lk == "pw2" || strings.Contains(lk, "pwd") && lk != "pwdlastset" {
				x[k] = "***"
			} else {
				x[k] = redact(val)
			}
		}
	case []any:
		for i := range x {
			x[i] = redact(x[i])
		}
	}
	return v
}

func audit(user, path string, body []byte, err error) {
	detail := ""
	if len(body) > 0 {
		var v any
		if json.Unmarshal(body, &v) == nil {
			b, _ := json.Marshal(redact(v))
			detail = string(b)
		}
	}
	if len(detail) > 600 {
		detail = detail[:600] + "…"
	}
	e := AuditEntry{Time: time.Now().UTC().Format(time.RFC3339), User: user, Action: strings.TrimPrefix(path, "/api/"), Detail: detail, OK: err == nil}
	if err != nil {
		e.Error = err.Error()
	}
	auditMu.Lock()
	defer auditMu.Unlock()
	auditRing = append(auditRing, e)
	if len(auditRing) > 2000 {
		auditRing = auditRing[len(auditRing)-2000:]
	}
	if auditFile != nil {
		b, _ := json.Marshal(e)
		auditFile.Write(append(b, '\n'))
	}
	log.Printf("AUDIT user=%s action=%s ok=%v %s", user, e.Action, e.OK, detail)
}

func apiAudit(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	auditMu.Lock()
	defer auditMu.Unlock()
	out := make([]AuditEntry, len(auditRing))
	for i, e := range auditRing {
		out[len(auditRing)-1-i] = e
	}
	return map[string]any{"entries": out, "file": auditFile != nil}, nil
}

// ---------- time helpers ----------

func ftToTime(n int64) time.Time { return time.Unix(n/10000000-11644473600, 0).UTC() }
func timeToFT(t time.Time) int64 { return (t.Unix() + 11644473600) * 10000000 }

func atoi64(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }

const day100ns = 864000000000
const min100ns = 600000000

// ---------- domain info ----------

func apiDomainInfo(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	out := map[string]any{}
	err := s.With(func(c *Conn) error {
		root, err := c.Read("", []string{"domainFunctionality", "forestFunctionality", "domainControllerFunctionality",
			"dnsHostName", "serverName", "schemaNamingContext", "rootDomainNamingContext", "defaultNamingContext",
			"configurationNamingContext", "namingContexts", "isGlobalCatalogReady", "supportedLDAPVersion"})
		if err != nil {
			return err
		}
		rd := map[string][]string{}
		for k := range root.Attrs {
			rd[k] = root.Strs(k)
		}
		out["rootDSE"] = rd

		type role struct {
			Role   string `json:"role"`
			Owner  string `json:"owner"`
			Server string `json:"server"`
			Site   string `json:"site"`
		}
		var roles []role
		for _, rl := range [][2]string{{"PDC emulator", s.base}, {"RID master", "CN=RID Manager$,CN=System," + s.base},
			{"Infrastructure master", "CN=Infrastructure," + s.base}, {"Schema master", s.schema}, {"Domain naming master", "CN=Partitions," + s.config}} {
			x := role{Role: rl[0]}
			if e, err := c.Read(rl[1], []string{"fSMORoleOwner"}); err == nil {
				if o := e.Get("fSMORoleOwner"); o != "" {
					x.Owner, x.Server, x.Site = o, dnLabel(o, 1), dnLabel(o, 3)
				}
			}
			roles = append(roles, x)
		}
		out["fsmo"] = roles

		list := domainControllers(c, s)
		out["dcs"] = list

		// Recycle Bin status
		if on, ok := recycleBinEnabled(c, s); ok {
			out["recycleBin"] = on
		}
		return nil
	})
	return out, err
}

// dcInfo is one domain controller (a server object with NTDS Settings).
type dcInfo struct {
	Name string `json:"name"`
	DNS  string `json:"dns"`
	Site string `json:"site"`
	GC   bool   `json:"gc"`
}

func domainControllers(c *Conn, s *Session) []*dcInfo {
	sites := "CN=Sites," + s.config
	dcs := map[string]*dcInfo{}
	if es, _, err := c.Search(sites, ScopeSub, "(objectClass=server)", []string{"dNSHostName"}, 1000); err == nil {
		for _, e := range es {
			dcs[strings.ToLower(e.DN)] = &dcInfo{Name: dnLabel(e.DN, 0), DNS: e.Get("dNSHostName"), Site: dnLabel(e.DN, 2)}
		}
	}
	if es, _, err := c.Search(sites, ScopeSub, "(objectClass=nTDSDSA)", []string{"options"}, 1000); err == nil {
		for _, e := range es {
			if d := dcs[strings.ToLower(parentDN(e.DN))]; d != nil {
				d.GC = atoi64(e.Get("options"))&1 != 0
			}
		}
	}
	list := []*dcInfo{}
	for k, d := range dcs {
		// only servers that have NTDS Settings are domain controllers
		if _, err := c.Read("CN=NTDS Settings,"+k, []string{"objectClass"}); err == nil {
			list = append(list, d)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	return list
}

// ---------- domain password policy ----------

var policyAttrs = []string{"minPwdLength", "pwdHistoryLength", "maxPwdAge", "minPwdAge", "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow", "pwdProperties"}

func intervalToUnits(raw string, unit int64) int64 {
	n := atoi64(raw)
	if n >= 0 || n == math.MinInt64 {
		return 0
	}
	return (-n) / unit
}

func unitsToInterval(v, unit int64) string {
	if v == 0 {
		return "0"
	}
	return strconv.FormatInt(-v*unit, 10)
}

type policyDTO struct {
	MinLength   int  `json:"minLength"`
	History     int  `json:"history"`
	MaxAgeDays  int  `json:"maxAgeDays"`
	MinAgeDays  int  `json:"minAgeDays"`
	Threshold   int  `json:"threshold"`
	DurationMin int  `json:"durationMin"`
	WindowMin   int  `json:"windowMin"`
	Complexity  bool `json:"complexity"`
	Reversible  bool `json:"reversible"`
}

func validatePolicy(p policyDTO) error {
	switch {
	case p.MinLength < 0 || p.MinLength > 255:
		return errors.New("minimum length must be 0–255")
	case p.History < 0 || p.History > 24:
		return errors.New("password history must be 0–24")
	case p.MaxAgeDays < 0 || p.MaxAgeDays > 999 || p.MinAgeDays < 0 || p.MinAgeDays > 998:
		return errors.New("password ages must be 0–999 days")
	case p.MaxAgeDays != 0 && p.MinAgeDays >= p.MaxAgeDays:
		return errors.New("minimum age must be less than maximum age")
	case p.Threshold < 0 || p.Threshold > 999:
		return errors.New("lockout threshold must be 0–999")
	case p.DurationMin < 0 || p.DurationMin > 99999 || p.WindowMin < 0 || p.WindowMin > 99999:
		return errors.New("lockout durations must be 0–99999 minutes")
	case p.Threshold > 0 && p.WindowMin < 1:
		return errors.New("lockout observation window must be at least 1 minute when lockout is enabled")
	case p.Threshold > 0 && p.DurationMin != 0 && p.WindowMin > p.DurationMin:
		return errors.New("observation window cannot exceed the lockout duration")
	}
	return nil
}

func apiPolicy(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	if r.Method == http.MethodGet {
		var e *Entry
		if err := s.With(func(c *Conn) (err error) { e, err = c.Read(s.base, policyAttrs); return }); err != nil {
			return nil, err
		}
		props := atoi64(e.Get("pwdProperties"))
		return policyDTO{
			MinLength: int(atoi64(e.Get("minPwdLength"))), History: int(atoi64(e.Get("pwdHistoryLength"))),
			MaxAgeDays: int(intervalToUnits(e.Get("maxPwdAge"), day100ns)), MinAgeDays: int(intervalToUnits(e.Get("minPwdAge"), day100ns)),
			Threshold: int(atoi64(e.Get("lockoutThreshold"))), DurationMin: int(intervalToUnits(e.Get("lockoutDuration"), min100ns)),
			WindowMin:  int(intervalToUnits(e.Get("lockOutObservationWindow"), min100ns)),
			Complexity: props&1 != 0, Reversible: props&16 != 0}, nil
	}
	var p policyDTO
	if err := decode(r, &p); err != nil {
		return nil, err
	}
	if err := validatePolicy(p); err != nil {
		return nil, err
	}
	return nil, s.With(func(c *Conn) error {
		e, err := c.Read(s.base, []string{"pwdProperties"})
		if err != nil {
			return err
		}
		props := atoi64(e.Get("pwdProperties"))
		props &^= 1 | 16
		if p.Complexity {
			props |= 1
		}
		if p.Reversible {
			props |= 16
		}
		maxAge := "-9223372036854775808" // never expires
		if p.MaxAgeDays > 0 {
			maxAge = unitsToInterval(int64(p.MaxAgeDays), day100ns)
		}
		rep := func(a, v string) Mod { return Mod{Op: 2, Attr: a, Vals: sv(v)} }
		return c.Modify(s.base, []Mod{rep("minPwdLength", strconv.Itoa(p.MinLength)), rep("pwdHistoryLength", strconv.Itoa(p.History)),
			rep("maxPwdAge", maxAge), rep("minPwdAge", unitsToInterval(int64(p.MinAgeDays), day100ns)),
			rep("lockoutThreshold", strconv.Itoa(p.Threshold)), rep("lockoutDuration", unitsToInterval(int64(p.DurationMin), min100ns)),
			rep("lockOutObservationWindow", unitsToInterval(int64(p.WindowMin), min100ns)), rep("pwdProperties", strconv.FormatInt(props, 10))})
	})
}

// ---------- alternative UPN suffixes ----------

// upnSuffixRe is a DNS-style name: one or more labels of letters, digits and hyphens (AD allows single-label suffixes such as "local").
var upnSuffixRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// apiUPNSuffixes reads or replaces uPNSuffixes on CN=Partitions,<configuration>, the same
// list that "Active Directory Domains and Trusts" edits. The change is made as the signed-in user.
func apiUPNSuffixes(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	dn := "CN=Partitions," + s.config
	if r.Method == http.MethodGet {
		var e *Entry
		if err := s.With(func(c *Conn) (err error) { e, err = c.Read(dn, []string{"uPNSuffixes"}); return }); err != nil {
			return nil, err
		}
		list := e.Strs("uPNSuffixes")
		sort.Strings(list)
		if list == nil {
			list = []string{}
		}
		return map[string]any{"suffixes": list}, nil
	}
	var in struct {
		Suffixes []string `json:"suffixes"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	seen := map[string]bool{strings.ToLower(realmFromBase(s.base)): true}
	vals := []string{}
	for _, x := range in.Suffixes {
		x = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(x), "@")))
		if !upnSuffixRe.MatchString(x) {
			return nil, fmt.Errorf("%q is not a valid UPN suffix", x)
		}
		if seen[x] {
			if x == strings.ToLower(realmFromBase(s.base)) {
				return nil, fmt.Errorf("%s is the domain's own suffix", x)
			}
			continue
		}
		seen[x] = true
		vals = append(vals, x)
	}
	sort.Strings(vals)
	return map[string]any{"suffixes": vals}, s.With(func(c *Conn) error {
		return c.Modify(dn, []Mod{{Op: 2, Attr: "uPNSuffixes", Vals: svs(vals)}})
	})
}

// ---------- fine-grained password policies ----------

type psoDTO struct {
	DN         string `json:"dn"`
	Name       string `json:"name"`
	Precedence int    `json:"precedence"`
	policyDTO
	AppliesTo []string `json:"appliesTo"`
}

func psoContainer(s *Session) string { return "CN=Password Settings Container,CN=System," + s.base }

func apiPSOList(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	out := []psoDTO{}
	err := s.With(func(c *Conn) error {
		es, _, err := c.Search(psoContainer(s), ScopeOne, "(objectClass=msDS-PasswordSettings)", []string{"*"}, 500)
		if err != nil {
			return err
		}
		for _, e := range es {
			out = append(out, psoDTO{DN: e.DN, Name: dnLabel(e.DN, 0), Precedence: int(atoi64(e.Get("msDS-PasswordSettingsPrecedence"))),
				policyDTO: policyDTO{
					MinLength: int(atoi64(e.Get("msDS-MinimumPasswordLength"))), History: int(atoi64(e.Get("msDS-PasswordHistoryLength"))),
					MaxAgeDays: int(intervalToUnits(e.Get("msDS-MaximumPasswordAge"), day100ns)), MinAgeDays: int(intervalToUnits(e.Get("msDS-MinimumPasswordAge"), day100ns)),
					Threshold: int(atoi64(e.Get("msDS-LockoutThreshold"))), DurationMin: int(intervalToUnits(e.Get("msDS-LockoutDuration"), min100ns)),
					WindowMin:  int(intervalToUnits(e.Get("msDS-LockoutObservationWindow"), min100ns)),
					Complexity: strings.EqualFold(e.Get("msDS-PasswordComplexityEnabled"), "TRUE"), Reversible: strings.EqualFold(e.Get("msDS-PasswordReversibleEncryptionEnabled"), "TRUE")},
				AppliesTo: e.Strs("msDS-PSOAppliesTo")})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Precedence < out[j].Precedence })
	return map[string]any{"psos": out}, err
}

func apiPSOSave(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var p psoDTO
	if err := decode(r, &p); err != nil {
		return nil, err
	}
	p.Name = strings.TrimSpace(p.Name)
	if p.DN == "" && p.Name == "" {
		return nil, errors.New("name is required")
	}
	if p.Precedence < 1 {
		return nil, errors.New("precedence must be 1 or greater")
	}
	if err := validatePolicy(p.policyDTO); err != nil {
		return nil, err
	}
	for _, d := range p.AppliesTo {
		if err := requireIn(s, d); err != nil {
			return nil, err
		}
	}
	b := func(v bool) string {
		if v {
			return "TRUE"
		}
		return "FALSE"
	}
	maxAge := "-9223372036854775808"
	if p.MaxAgeDays > 0 {
		maxAge = unitsToInterval(int64(p.MaxAgeDays), day100ns)
	}
	attrs := []Mod{
		{Attr: "msDS-PasswordSettingsPrecedence", Vals: sv(strconv.Itoa(p.Precedence))},
		{Attr: "msDS-PasswordReversibleEncryptionEnabled", Vals: sv(b(p.Reversible))},
		{Attr: "msDS-PasswordHistoryLength", Vals: sv(strconv.Itoa(p.History))},
		{Attr: "msDS-PasswordComplexityEnabled", Vals: sv(b(p.Complexity))},
		{Attr: "msDS-MinimumPasswordLength", Vals: sv(strconv.Itoa(p.MinLength))},
		{Attr: "msDS-MinimumPasswordAge", Vals: sv(unitsToInterval(int64(p.MinAgeDays), day100ns))},
		{Attr: "msDS-MaximumPasswordAge", Vals: sv(maxAge)},
		{Attr: "msDS-LockoutThreshold", Vals: sv(strconv.Itoa(p.Threshold))},
		{Attr: "msDS-LockoutObservationWindow", Vals: sv(unitsToInterval(int64(p.WindowMin), min100ns))},
		{Attr: "msDS-LockoutDuration", Vals: sv(unitsToInterval(int64(p.DurationMin), min100ns))},
	}
	return nil, s.With(func(c *Conn) error {
		if p.DN == "" {
			attrs = append([]Mod{{Attr: "objectClass", Vals: svs([]string{"top", "msDS-PasswordSettings"})}}, attrs...)
			if len(p.AppliesTo) > 0 {
				attrs = append(attrs, Mod{Attr: "msDS-PSOAppliesTo", Vals: svs(p.AppliesTo)})
			}
			return c.Add("CN="+escapeRDN(p.Name)+","+psoContainer(s), attrs)
		}
		if !strings.EqualFold(parentDN(p.DN), psoContainer(s)) {
			return errors.New("not a password settings object")
		}
		for i := range attrs {
			attrs[i].Op = 2
		}
		attrs = append(attrs, Mod{Op: 2, Attr: "msDS-PSOAppliesTo", Vals: svs(p.AppliesTo)})
		return c.Modify(p.DN, attrs)
	})
}

// ---------- reports ----------

type ReportRow struct {
	Name   string `json:"name"`
	Sam    string `json:"sam"`
	Type   string `json:"type"`
	Detail string `json:"detail"`
	DN     string `json:"dn"`
}

const (
	fUser = "(&(objectClass=user)(!(objectClass=computer)))"
	fComp = "(objectClass=computer)"
)

func uacBit(b int) string {
	return "(userAccountControl:1.2.840.113556.1.4.803:=" + strconv.Itoa(b) + ")"
}

var reportAttrs = []string{"name", "sAMAccountName", "objectClass", "userAccountControl", "lastLogonTimestamp", "pwdLastSet", "lockoutTime", "whenCreated", "accountExpires", "member", "description"}

func genTime(v string) time.Time {
	if len(v) >= 14 {
		if t, err := time.Parse("20060102150405", v[:14]); err == nil {
			return t
		}
	}
	return time.Time{}
}

func apiReport(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	name := r.URL.Query().Get("name")
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	if days <= 0 || days > 3650 {
		days = 90
	}
	now := time.Now()
	var filter, note string
	var post func(c *Conn, e *Entry) (string, bool)
	var cutoff = timeToFT(now.AddDate(0, 0, -days))
	last := func(e *Entry) string {
		if v := atoi64(e.Get("lastLogonTimestamp")); v > 0 {
			return "last logon " + ftToTime(v).Format("2006-01-02")
		}
		return "never logged on"
	}
	stale := func(base string) {
		filter = "(&" + base + "(!" + uacBit(2) + ")(|(!(lastLogonTimestamp=*))(lastLogonTimestamp<=" + strconv.FormatInt(cutoff, 10) + ")))"
		post = func(c *Conn, e *Entry) (string, bool) {
			if atoi64(e.Get("lastLogonTimestamp")) == 0 && genTime(e.Get("whenCreated")).After(now.AddDate(0, 0, -days)) {
				return "", false // too new to call stale
			}
			return last(e), true
		}
		note = fmt.Sprintf("Enabled accounts with no logon in %d days (lastLogonTimestamp is replicated only every ~14 days).", days)
	}
	switch name {
	case "stale-users":
		stale(fUser)
	case "stale-computers":
		stale(fComp)
	case "disabled":
		filter = "(&" + fUser + uacBit(2) + ")"
		post = func(c *Conn, e *Entry) (string, bool) { return "disabled", true }
	case "locked":
		filter = "(&" + fUser + "(lockoutTime>=1))"
		var durMin int64
		s.With(func(c *Conn) error {
			if e, err := c.Read(s.base, []string{"lockoutDuration"}); err == nil {
				durMin = intervalToUnits(e.Get("lockoutDuration"), min100ns)
			}
			return nil
		})
		post = func(c *Conn, e *Entry) (string, bool) {
			t := ftToTime(atoi64(e.Get("lockoutTime")))
			if durMin > 0 && t.Add(time.Duration(durMin)*time.Minute).Before(now) {
				return "", false // lock has expired
			}
			return "locked since " + t.Format("2006-01-02 15:04 UTC"), true
		}
		note = "Accounts currently locked out (expired lockouts are excluded)."
	case "never-expire":
		filter = "(&" + fUser + "(!" + uacBit(2) + ")" + uacBit(65536) + ")"
		post = func(c *Conn, e *Entry) (string, bool) { return "password never expires", true }
	case "expiring":
		filter = "(&" + fUser + "(!" + uacBit(2) + ")(!" + uacBit(65536) + ")(pwdLastSet>=1))"
		var maxAge int64
		s.With(func(c *Conn) error {
			if e, err := c.Read(s.base, []string{"maxPwdAge"}); err == nil {
				maxAge = intervalToUnits(e.Get("maxPwdAge"), day100ns)
			}
			return nil
		})
		if maxAge == 0 {
			return map[string]any{"rows": []ReportRow{}, "note": "The domain password policy has no maximum password age, so passwords do not expire."}, nil
		}
		note = fmt.Sprintf("Passwords that expired or expire within %d days, using the domain policy (%d-day maximum age). Accounts under a fine-grained policy may differ.", days, maxAge)
		post = func(c *Conn, e *Entry) (string, bool) {
			exp := ftToTime(atoi64(e.Get("pwdLastSet"))).AddDate(0, 0, int(maxAge))
			if exp.After(now.AddDate(0, 0, days)) {
				return "", false
			}
			if exp.Before(now) {
				return "expired " + exp.Format("2006-01-02"), true
			}
			return fmt.Sprintf("expires %s (in %d days)", exp.Format("2006-01-02"), int(exp.Sub(now).Hours()/24)), true
		}
	case "empty-groups":
		filter = "(&(objectClass=group)(!(member=*))(!(isCriticalSystemObject=TRUE)))"
		post = func(c *Conn, e *Entry) (string, bool) { return "no members", true }
	case "no-preauth":
		filter = "(&" + fUser + uacBit(4194304) + ")"
		post = func(c *Conn, e *Entry) (string, bool) { return "Kerberos pre-authentication not required", true }
	case "unconstrained":
		filter = "(&(objectClass=user)" + uacBit(524288) + "(!" + uacBit(8192) + "))"
		post = func(c *Conn, e *Entry) (string, bool) { return "trusted for unconstrained delegation", true }
		note = "Non-DC accounts trusted for unconstrained Kerberos delegation."
	case "privileged":
		return reportPrivileged(s)
	default:
		return nil, errors.New("unknown report")
	}
	rows := []ReportRow{}
	trunc := false
	err := s.With(func(c *Conn) error {
		es, t, err := c.Search(s.base, ScopeSub, filter, reportAttrs, 5000)
		trunc = t
		if err != nil {
			return err
		}
		for _, e := range es {
			d, ok := post(c, e)
			if !ok {
				continue
			}
			rows = append(rows, ReportRow{Name: e.Get("name"), Sam: e.Get("sAMAccountName"), Type: TYPELBL[kindOf(e.Strs("objectClass"))], Detail: d, DN: e.DN})
		}
		return nil
	})
	sort.Slice(rows, func(i, j int) bool { return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name) })
	return map[string]any{"rows": rows, "truncated": trunc, "note": note}, err
}

var TYPELBL = map[string]string{"user": "User", "computer": "Computer", "group": "Group", "ou": "OU", "container": "Container"}

func reportPrivileged(s *Session) (any, error) {
	groups := []string{"Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Server Operators", "Backup Operators", "Group Policy Creator Owners", "DnsAdmins"}
	byDN := map[string]*ReportRow{}
	var order []string
	err := s.With(func(c *Conn) error {
		for _, g := range groups {
			ge, _, err := c.Search(s.base, ScopeSub, "(&(objectClass=group)(sAMAccountName="+EscapeFilter(g)+"))", []string{"name"}, 1)
			if err != nil || len(ge) == 0 {
				continue
			}
			es, _, err := c.Search(s.base, ScopeSub, "(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:="+EscapeFilter(ge[0].DN)+"))", reportAttrs, 5000)
			if err != nil {
				continue
			}
			for _, e := range es {
				row := byDN[e.DN]
				if row == nil {
					row = &ReportRow{Name: e.Get("name"), Sam: e.Get("sAMAccountName"), Type: TYPELBL[kindOf(e.Strs("objectClass"))], DN: e.DN}
					byDN[e.DN] = row
					order = append(order, e.DN)
				}
				if row.Detail != "" {
					row.Detail += ", "
				}
				row.Detail += g
			}
		}
		return nil
	})
	rows := []ReportRow{}
	for _, d := range order {
		rows = append(rows, *byDN[d])
	}
	sort.Slice(rows, func(i, j int) bool { return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name) })
	return map[string]any{"rows": rows, "note": "Accounts that are (directly or through nested groups) members of built-in privileged groups. The Detail column lists the groups."}, err
}

// ---------- recycle bin ----------

const recycleBinGUID = "766ddcd8-acd0-445e-f3b9-a7f9b6744f2a"

func recycleBinFeatureDN(s *Session) string {
	return "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services," + s.config
}

// recycleBinEnabled reports whether the forest-wide Recycle Bin feature is on. The feature is recorded two ways: the
// forest's Partitions container lists it in msDS-EnabledFeature, and the feature object carries the back-link
// msDS-EnabledFeatureBL. Either is taken as proof; ok is false when neither can be read.
func recycleBinEnabled(c *Conn, s *Session) (on, ok bool) {
	feat := recycleBinFeatureDN(s)
	if e, err := c.Read("CN=Partitions,"+s.config, []string{"msDS-EnabledFeature"}); err == nil {
		ok = true
		for _, v := range e.Strs("msDS-EnabledFeature") {
			if strings.EqualFold(v, feat) {
				return true, true
			}
		}
	}
	if e, err := c.Read(feat, []string{"msDS-EnabledFeatureBL"}); err == nil {
		ok = true
		if len(e.Strs("msDS-EnabledFeatureBL")) > 0 {
			return true, true
		}
	}
	return false, ok
}

// apiRecycleEnable switches the Recycle Bin on for the forest, like Enable-ADOptionalFeature: it adds
// "<Partitions DN>:<feature GUID>" to the rootDSE attribute enableOptionalFeature. This cannot be undone, needs
// forest functional level 2008 R2 or higher, and AD only lets Enterprise Admins do it, so a refusal is passed on.
func apiRecycleEnable(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	if r.Method != http.MethodPost {
		return nil, errors.New("POST required")
	}
	err := s.With(func(c *Conn) error {
		if on, ok := recycleBinEnabled(c, s); ok && on {
			return errors.New("the Recycle Bin is already enabled")
		}
		root, err := c.Read("", []string{"forestFunctionality"})
		if err != nil {
			return err
		}
		if lvl := atoi64(root.Get("forestFunctionality")); root.Get("forestFunctionality") != "" && lvl < 4 {
			return fmt.Errorf("the forest functional level must be 2008 R2 or higher (it is %d); raise it first, e.g. samba-tool domain level raise --forest-level=2008_R2", lvl)
		}
		val := "CN=Partitions," + s.config + ":" + recycleBinGUID
		err = c.Modify("", []Mod{{Op: 0, Attr: "enableOptionalFeature", Vals: sv(val)}})
		var le *LDAPError
		if errors.As(err, &le) && (le.Code == 50 || le.Code == 53) && samDBUsable() {
			// Samba only takes enableOptionalFeature from its own local system context, never from a remote
			// bind, even an Enterprise Admin's. Retry locally, but only for a verified Enterprise Admin.
			ea, merr := isEnterpriseAdmin(c, s)
			if merr != nil || !ea {
				return fmt.Errorf("%w (only an Enterprise Admin may enable it)", err)
			}
			log.Printf("recycle bin: LDAP refused for %s (%v); enabling locally in %s", s.user, err, samDB)
			if lerr := ldbModifyLocal(val); lerr != nil {
				return fmt.Errorf("%w; local fallback failed: %v", err, lerr)
			}
			return nil
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	var on bool
	_ = s.With(func(c *Conn) error { on, _ = recycleBinEnabled(c, s); return nil })
	return map[string]bool{"enabled": on}, nil
}

// apiRecycleStatus tells the delete dialog whether a delete will land in the Recycle Bin: the DC only recycles when the
// forest feature is on; otherwise the object is gone for good. known is false when the feature could not be read.
func apiRecycleStatus(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var on, known bool
	err := s.With(func(c *Conn) error { on, known = recycleBinEnabled(c, s); return nil })
	return map[string]bool{"enabled": on, "known": known}, err
}

type deletedDTO struct {
	DN         string `json:"dn"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Sam        string `json:"sam"`
	LastParent string `json:"lastParent"`
	When       string `json:"when"`
	Recycled   bool   `json:"recycled"`
}

func showDeletedCtl() []byte { return control(oidShowDeleted, true, nil) }

func hasClass(classes []string, want string) bool {
	for _, c := range classes {
		if strings.EqualFold(c, want) {
			return true
		}
	}
	return false
}

func listDeleted(c *Conn, s *Session) (out []deletedDTO, trunc bool, err error) {
	out = []deletedDTO{}
	// The Recycle Bin is forest-wide but each partition has its own Deleted Objects: users, groups and OUs are in the
	// domain's, subnets, sites and site links in the Configuration partition's. Look in both.
	attrs := []string{"msDS-LastKnownRDN", "lastKnownParent", "objectClass", "sAMAccountName", "whenChanged", "isRecycled", "name", "dnsRecord"}
	var es []*Entry
	seen := map[string]bool{}
	for _, base := range []string{s.base, s.config} {
		if base == "" {
			continue
		}
		got, t, err := c.SearchCtl(base, ScopeSub, "(isDeleted=TRUE)", attrs, 2000, showDeletedCtl())
		trunc = trunc || t
		if err != nil {
			if base == s.base {
				return out, trunc, err
			}
			continue // the Configuration partition is a bonus: its refusal must not hide the domain's list
		}
		for _, e := range got {
			if !seen[strings.ToLower(e.DN)] {
				seen[strings.ToLower(e.DN)] = true
				es = append(es, e)
			}
		}
	}
	t := trunc
	for _, e := range es {
		// deleting the last record of a DNS name also deletes the then-empty node; the record itself is in the DNS bin
		if len(e.Attrs["dnsRecord"]) == 0 && hasClass(e.Strs("objectClass"), "dnsNode") {
			continue
		}
		n := e.Get("msDS-LastKnownRDN")
		if n == "" {
			n = strings.SplitN(e.Get("name"), "\n", 2)[0]
		}
		if strings.EqualFold(n, "Deleted Objects") {
			continue
		}
		when := ""
		if t := genTime(e.Get("whenChanged")); !t.IsZero() {
			when = t.Format("2006-01-02 15:04 UTC")
		}
		out = append(out, deletedDTO{DN: e.DN, Name: n, Type: kindOf(e.Strs("objectClass")), Sam: e.Get("sAMAccountName"),
			LastParent: e.Get("lastKnownParent"), When: when, Recycled: strings.EqualFold(e.Get("isRecycled"), "TRUE")})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].When > out[j].When })
	return out, t, nil
}

func apiDeleted(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var out []deletedDTO
	var trunc bool
	err := s.With(func(c *Conn) (e error) { out, trunc, e = listDeleted(c, s); return e })
	if out == nil {
		out = []deletedDTO{}
	}
	return map[string]any{"objects": out, "truncated": trunc, "dns": dnsBinList()}, err
}

// Local fallbacks for apiPurge, variables so tests can replace them. A DC may refuse to remove an object from Deleted
// Objects over LDAP (AD does; Samba only expunges tombstones itself), so after that refusal, as root with sam.ldb
// present and only for a verified Domain/Enterprise Admin, the work is done locally: samba-tool's tombstone expunge for
// the whole bin, ldbdel for one object. Like the Recycle Bin enable fallback, it is logged.
var sambaToolRun = func(args ...string) error {
	bin, err := exec.LookPath("samba-tool")
	if err != nil {
		return errors.New("samba-tool not found")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, bin, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("samba-tool: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

var ldbDelLocal = func(dn string) error {
	bin, err := exec.LookPath("ldbdel")
	if err != nil {
		return errors.New("ldbdel not found (install ldb-tools)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, bin, "-H", samDB, "--controls=show_deleted:1", dn).CombinedOutput(); err != nil {
		return fmt.Errorf("ldbdel: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isRefusal(err error) bool {
	var le *LDAPError
	return errors.As(err, &le) && (le.Code == 50 || le.Code == 53)
}

// apiPurge removes one object from the Recycle Bin for good, or (all) every object in it. The LDAP delete runs as the
// signed-in user, so AD's own rules decide; when the DC refuses, see the local fallback above.
func apiPurge(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		DN  string `json:"dn"`
		All bool   `json:"all"`
		DNS string `json:"dns"` // id of one deleted DNS record
		// Local: the person agreed to remove it from this DC's own database when the DC refuses the LDAP delete
		// (which nothing replicates). Peers: other DCs' goaduc to do the same on, each with the certificate fingerprint
		// the person approved.
		Local bool `json:"local"`
		Peers []struct {
			Host        string `json:"host"`
			Fingerprint string `json:"fingerprint"`
		} `json:"peers"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if in.DNS != "" {
		if err := requireDNSBinAdmin(s); err != nil {
			return nil, err
		}
		if dnsBinRemove(in.DNS) == 0 {
			return nil, errors.New("not in the Recycle Bin")
		}
		return map[string]int{"deleted": 1}, nil
	}
	dnsGone := 0
	if in.All && len(dnsBinList()) > 0 {
		if err := requireDNSBinAdmin(s); err != nil {
			return nil, err
		}
		dnsGone = dnsBinRemove("")
	}
	var dns []string
	if in.All {
		err := s.With(func(c *Conn) error {
			l, _, e := listDeleted(c, s)
			for _, d := range l {
				dns = append(dns, d.DN)
			}
			return e
		})
		if err != nil {
			return nil, err
		}
	} else {
		if err := requireIn(s, in.DN); err != nil {
			return nil, err
		}
		if !strings.Contains(strings.ToLower(in.DN), ",cn=deleted objects,") {
			return nil, errors.New("not an object in the Recycle Bin")
		}
		dns = []string{in.DN}
	}
	var first error
	refused := false
	n := 0
	for _, dn := range dns {
		err := s.With(func(c *Conn) error { return c.DeleteDeleted(dn) })
		if err == nil {
			n++
			continue
		}
		if first == nil {
			first = err
		}
		if isRefusal(err) {
			refused = true
			break // the rest would be refused alike
		}
	}
	if refused && samDBUsable() {
		var admin bool
		if merr := s.With(func(c *Conn) (e error) { admin, e = isDomainAdmin(c, s); return e }); merr != nil || !admin {
			return map[string]int{"deleted": n}, fmt.Errorf("%w (only a Domain Admin or Enterprise Admin can use the local fallback)", first)
		}
		if !in.Local { // ask first: this is not replicated; the page offers the other DCs too
			resp := map[string]any{"needsLocal": true, "deleted": n, "error": first.Error(), "peers": []peerInfo{}}
			var hosts []string
			var server string
			_ = s.With(func(c *Conn) error {
				hosts, _ = peerHosts(c, s)
				if root, err := c.Read("", []string{"dnsHostName"}); err == nil {
					server = root.Get("dnsHostName")
				}
				return nil
			})
			resp["server"] = server
			peers := make([]peerInfo, len(hosts))
			var wg sync.WaitGroup
			for i, h := range hosts {
				wg.Add(1)
				go func(i int, h string) { defer wg.Done(); peers[i] = probePeer(h) }(i, h)
			}
			wg.Wait()
			resp["peers"] = peers
			return resp, nil
		}
		log.Printf("recycle bin: LDAP refused for %s (%v); removing locally in %s", s.user, first, samDB)
		var lerr error
		if in.All {
			lerr = sambaToolRun("domain", "tombstones", "expunge", "--tombstone-lifetime=0", "-H", samDB)
		} else {
			lerr = ldbDelLocal(in.DN)
		}
		if lerr != nil {
			return map[string]int{"deleted": n}, fmt.Errorf("%w; local fallback failed: %v", first, lerr)
		}
		if in.All {
			left := 0
			_ = s.With(func(c *Conn) error { l, _, _ := listDeleted(c, s); left = len(l); return nil })
			n = len(dns) - left
		} else {
			n = 1
		}
		first = nil
		if in.All && n < len(dns) {
			first = fmt.Errorf("local expunge left %d of %d objects", len(dns)-n, len(dns))
		}
	}
	var peerRes []peerResult
	if first == nil && in.Local && len(in.Peers) > 0 {
		var hosts []string
		_ = s.With(func(c *Conn) error { hosts, _ = peerHosts(c, s); return nil })
		known := map[string]bool{}
		for _, h := range hosts {
			known[h] = true
		}
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, p := range in.Peers {
			host := strings.ToLower(strings.TrimSpace(p.Host))
			if !known[host] { // only domain controllers the directory lists, never an address from the browser
				peerRes = append(peerRes, peerResult{Host: p.Host, Error: "not a domain controller of this domain"})
				continue
			}
			body := map[string]any{"all": in.All}
			if !in.All {
				body["dn"] = in.DN
			}
			wg.Add(1)
			go func(host, fp string) {
				defer wg.Done()
				r := purgeOnPeer(s, host, fp, body)
				mu.Lock()
				peerRes = append(peerRes, r)
				mu.Unlock()
			}(host, p.Fingerprint)
		}
		wg.Wait()
		sort.Slice(peerRes, func(i, j int) bool { return peerRes[i].Host < peerRes[j].Host })
	}
	if first == nil && len(peerRes) > 0 {
		return map[string]any{"deleted": n + dnsGone, "peers": peerRes}, nil
	}
	if first != nil {
		if len(dns) == 1 {
			return map[string]int{"deleted": n}, first
		}
		return map[string]int{"deleted": n}, fmt.Errorf("%d of %d removed: %w", n, len(dns), first)
	}
	return map[string]int{"deleted": n + dnsGone}, nil
}

func apiRestore(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		DN     string `json:"dn"`
		Parent string `json:"parent"`
		Name   string `json:"name"`
		Type   string `json:"type"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.DN); err != nil {
		return nil, err
	}
	if err := requireIn(s, in.Parent); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	rdnType := "CN"
	if in.Type == "ou" {
		rdnType = "OU"
	}
	newDN := rdnType + "=" + escapeRDN(in.Name) + "," + in.Parent
	err := s.With(func(c *Conn) error {
		if _, err := c.Read(in.Parent, []string{"objectClass"}); err != nil {
			return fmt.Errorf("destination container: %w", err)
		}
		return c.ModifyCtl(in.DN, []Mod{{Op: 1, Attr: "isDeleted"}, {Op: 0, Attr: "distinguishedName", Vals: sv(newDN)}}, showDeletedCtl())
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{"dn": newDN}, nil
}

// samDB is Samba's local directory database, used only by the Recycle Bin fallback (-sam-db / ADUC_SAMDB).
var samDB = "/var/lib/samba/private/sam.ldb"

// ldbModifyLocal applies a rootDSE enableOptionalFeature as the local system user (ldbmodify on sam.ldb). It is a
// variable so tests can replace it.
var ldbModifyLocal = func(val string) error {
	bin, err := exec.LookPath("ldbmodify")
	if err != nil {
		return errors.New("ldbmodify not found (install ldb-tools)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "-H", samDB)
	cmd.Stdin = strings.NewReader("dn:\nchangetype: modify\nadd: enableOptionalFeature\nenableOptionalFeature: " + val + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ldbmodify: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// samDBUsable reports whether the local fallback can work: running as root with the database present.
var samDBUsable = func() bool {
	if os.Geteuid() != 0 {
		return false
	}
	st, err := os.Stat(samDB)
	return err == nil && !st.IsDir()
}

// isEnterpriseAdmin asks the directory, as the signed-in user, whether that user is (transitively) in Enterprise Admins.
func isEnterpriseAdmin(c *Conn, s *Session) (bool, error) {
	name := s.user
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	sam := name
	if i := strings.IndexByte(sam, '@'); i >= 0 {
		sam = sam[:i]
	}
	ea := "CN=Enterprise Admins,CN=Users," + s.base
	f := "(&(objectClass=user)(|(sAMAccountName=" + EscapeFilter(sam) + ")(userPrincipalName=" + EscapeFilter(name) + "))(memberOf:1.2.840.113556.1.4.1941:=" + EscapeFilter(ea) + "))"
	es, _, err := c.Search(s.base, ScopeSub, f, []string{"sAMAccountName"}, 1)
	if err != nil {
		return false, err
	}
	return len(es) > 0, nil
}
