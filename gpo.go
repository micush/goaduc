package main

// Group Policy: the GPO objects and their links (LDAP). The settings themselves are files in SYSVOL, handled in
// gpofiles.go. Every LDAP operation runs as the signed-in user; every SYSVOL write is gated by an LDAP write the same
// user must succeed at first (see gpoCommit), because the files are written by this process, not by that user.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func registerGPO(mux *http.ServeMux) {
	mux.HandleFunc("/api/gpo/list", auth(apiGPOList))
	mux.HandleFunc("/api/gpo/create", auth(apiGPOCreate))
	mux.HandleFunc("/api/gpo/delete", auth(apiGPODelete))
	mux.HandleFunc("/api/gpo/rename", auth(apiGPORename))
	mux.HandleFunc("/api/gpo/status", auth(apiGPOStatus))
	mux.HandleFunc("/api/gpo/ext", auth(apiGPOExt))
	mux.HandleFunc("/api/gpo/link", auth(apiGPOLink))
	mux.HandleFunc("/api/gpo/unlink", auth(apiGPOUnlink))
	mux.HandleFunc("/api/gpo/move", auth(apiGPOMove))
	mux.HandleFunc("/api/gpo/inherit", auth(apiGPOInherit))
	mux.HandleFunc("/api/gpo/registry", auth(apiGPORegistry))
	mux.HandleFunc("/api/gpo/registry/save", auth(apiGPORegistrySave))
	mux.HandleFunc("/api/gpo/security", auth(apiGPOSecurity))
	mux.HandleFunc("/api/gpo/security/save", auth(apiGPOSecuritySave))
	mux.HandleFunc("/api/gpo/files", auth(apiGPOFiles))
	mux.HandleFunc("/api/gpo/file", auth(apiGPOFile))
	mux.HandleFunc("/api/gpo/file/save", auth(apiGPOFileSave))
	mux.HandleFunc("/api/gpo/file/delete", auth(apiGPOFileDelete))
	mux.HandleFunc("/api/gpo/file/mkdir", auth(apiGPOMkdir))
}

var guidRe = regexp.MustCompile(`^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$`)

// normGUID validates a GPO GUID in braces and returns it upper-cased.
func normGUID(g string) (string, error) {
	g = strings.TrimSpace(g)
	if !guidRe.MatchString(g) {
		return "", errors.New("invalid GPO identifier")
	}
	return strings.ToUpper(g), nil
}

func newGUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("{%08X-%04X-%04X-%04X-%012X}", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func policiesDN(s *Session) string { return "CN=Policies,CN=System," + s.base }
func gpoDN(s *Session, guid string) string {
	return "CN=" + guid + "," + policiesDN(s)
}

// dnsDomainOf turns DC=a,DC=b,DC=c into a.b.c.
func dnsDomainOf(base string) string {
	var parts []string
	for _, p := range splitDN(base) {
		if i := strings.IndexByte(p, '='); i > 0 && strings.EqualFold(p[:i], "DC") {
			parts = append(parts, p[i+1:])
		}
	}
	return strings.ToLower(strings.Join(parts, "."))
}

// ---------- gPLink ----------

type glink struct {
	DN  string
	Opt int // 1 = link disabled, 2 = enforced
}

var gplinkRe = regexp.MustCompile(`\[LDAP://([^;\]]*);(\d+)\]`)

// parseGPLink returns the links in attribute order. In the attribute the LAST link has the highest precedence
// (link order 1 in the console); the first has the lowest.
func parseGPLink(v string) []glink {
	var out []glink
	for _, m := range gplinkRe.FindAllStringSubmatch(v, -1) {
		n, _ := strconv.Atoi(m[2])
		out = append(out, glink{DN: m[1], Opt: n})
	}
	return out
}

func formatGPLink(l []glink) string {
	var sb strings.Builder
	for _, x := range l {
		sb.WriteString("[LDAP://" + x.DN + ";" + strconv.Itoa(x.Opt) + "]")
	}
	return sb.String()
}

var linkGUIDRe = regexp.MustCompile(`(?i)^cn=(\{[0-9a-f-]{36}\})`)

func linkGUID(dn string) string {
	if m := linkGUIDRe.FindStringSubmatch(dn); m != nil {
		return strings.ToUpper(m[1])
	}
	return ""
}

func (l glink) guid() string { return linkGUID(l.DN) }

// ---------- list ----------

type gpoLinkDTO struct {
	Target     string `json:"target"`
	TargetName string `json:"targetName"`
	Kind       string `json:"kind"`
	Order      int    `json:"order"` // 1 = highest precedence
	Of         int    `json:"of"`
	Enforced   bool   `json:"enforced"`
	Disabled   bool   `json:"disabled"`
	Block      bool   `json:"block"` // the target blocks inheritance
}

type gpoDTO struct {
	GUID     string       `json:"guid"`
	Name     string       `json:"name"`
	Flags    int          `json:"flags"`
	Version  int64        `json:"version"`
	UserVer  int64        `json:"userVersion"`
	MachVer  int64        `json:"machineVersion"`
	Created  string       `json:"created"`
	Changed  string       `json:"changed"`
	Path     string       `json:"path"`
	MachExt  string       `json:"machineExt"`
	UserExt  string       `json:"userExt"`
	Links    []gpoLinkDTO `json:"links"`
	DN       string       `json:"dn"`
	GPTVer   int64        `json:"gptVersion"`
	GPTKnown bool         `json:"gptKnown"`
}

func fmtLDAPTime(s string) string {
	if len(s) >= 14 {
		return s[0:4] + "-" + s[4:6] + "-" + s[6:8] + " " + s[8:10] + ":" + s[10:12] + ":" + s[12:14]
	}
	return s
}

func kindOfTarget(oc []string) string {
	switch {
	case has(oc, "site"):
		return "site"
	case has(oc, "organizationalUnit"):
		return "ou"
	case has(oc, "domainDNS") || has(oc, "domain"):
		return "domain"
	}
	return "container"
}

func apiGPOList(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	gpos := []gpoDTO{}
	var trunc bool
	err := s.With(func(c *Conn) error {
		es, t, err := c.Search(policiesDN(s), ScopeOne, "(objectClass=groupPolicyContainer)",
			[]string{"displayName", "flags", "versionNumber", "gPCFileSysPath", "whenCreated", "whenChanged", "gPCMachineExtensionNames", "gPCUserExtensionNames", "name"}, 5000)
		if err != nil {
			return err
		}
		trunc = t
		byGUID := map[string]int{}
		for _, e := range es {
			g := linkGUID(e.DN)
			if g == "" {
				continue
			}
			v := atoi64(e.Get("versionNumber"))
			d := gpoDTO{GUID: g, DN: e.DN, Name: e.Get("displayName"), Flags: int(atoi64(e.Get("flags"))), Version: v, UserVer: v >> 16 & 0xffff, MachVer: v & 0xffff,
				Created: fmtLDAPTime(e.Get("whenCreated")), Changed: fmtLDAPTime(e.Get("whenChanged")), Path: e.Get("gPCFileSysPath"),
				MachExt: e.Get("gPCMachineExtensionNames"), UserExt: e.Get("gPCUserExtensionNames"), Links: []gpoLinkDTO{}}
			if d.Name == "" {
				d.Name = g
			}
			if dir, err := gpoDir(s, g); err == nil {
				if gv, ok := readGPTVersion(dir); ok {
					d.GPTVer, d.GPTKnown = gv, true
				}
			}
			byGUID[g] = len(gpos)
			gpos = append(gpos, d)
		}
		// links: every object with a gPLink in the domain, plus the sites
		for _, base := range []string{s.base, "CN=Sites," + s.config} {
			les, _, err := c.Search(base, ScopeSub, "(gPLink=*)", []string{"gPLink", "gPOptions", "name", "objectClass"}, 5000)
			if err != nil {
				if base == s.base {
					return err
				}
				continue // no Sites container readable: not fatal
			}
			for _, le := range les {
				links := parseGPLink(le.Get("gPLink"))
				kind := kindOfTarget(le.Strs("objectClass"))
				block := atoi64(le.Get("gPOptions"))&1 != 0
				for i, l := range links {
					idx, ok := byGUID[l.guid()]
					if !ok {
						continue
					}
					name := le.Get("name")
					if name == "" {
						name = dnLabel(le.DN, 0)
					}
					gpos[idx].Links = append(gpos[idx].Links, gpoLinkDTO{Target: le.DN, TargetName: name, Kind: kind, Order: len(links) - i, Of: len(links),
						Enforced: l.Opt&2 != 0, Disabled: l.Opt&1 != 0, Block: block})
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(gpos, func(i, j int) bool { return strings.ToLower(gpos[i].Name) < strings.ToLower(gpos[j].Name) })
	for i := range gpos {
		l := gpos[i].Links
		sort.Slice(l, func(a, b int) bool { return strings.ToLower(l[a].Target) < strings.ToLower(l[b].Target) })
	}
	return map[string]any{"gpos": gpos, "truncated": trunc, "sysvol": sysvolInfo(s)}, nil
}

// ---------- create / delete / rename / status ----------

func apiGPOCreate(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		Name   string `json:"name"`
		LinkTo string `json:"linkTo"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 200 || strings.ContainsAny(in.Name, "\x00\r\n") {
		return nil, errors.New("a name is required")
	}
	pol, err := policiesDir(s)
	if err != nil {
		return nil, err
	}
	if in.LinkTo != "" {
		if err := requireIn(s, in.LinkTo); err != nil {
			return nil, err
		}
	}
	guid := newGUID()
	dn := gpoDN(s, guid)
	dom := dnsDomainOf(s.base)
	err = s.With(func(c *Conn) error {
		if es, _, err := c.Search(policiesDN(s), ScopeOne, "(displayName="+EscapeFilter(in.Name)+")", []string{"name"}, 1); err == nil && len(es) > 0 {
			return errors.New("a GPO with that name already exists")
		}
		if err := c.Add(dn, []Mod{
			{Attr: "objectClass", Vals: svs([]string{"top", "container", "groupPolicyContainer"})},
			{Attr: "displayName", Vals: sv(in.Name)}, {Attr: "flags", Vals: sv("0")}, {Attr: "versionNumber", Vals: sv("0")},
			{Attr: "gPCFunctionalityVersion", Vals: sv("2")},
			{Attr: "gPCFileSysPath", Vals: sv(`\\` + dom + `\sysvol\` + dom + `\Policies\` + guid)},
		}); err != nil {
			return err
		}
		for _, sub := range []string{"User", "Machine"} {
			if err := c.Add("CN="+sub+","+dn, []Mod{{Attr: "objectClass", Vals: svs([]string{"top", "container"})}}); err != nil {
				_ = c.Delete(dn, true)
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := createGPOFiles(pol, guid); err != nil {
		_ = s.With(func(c *Conn) error { return c.Delete(dn, true) })
		return nil, fmt.Errorf("could not create the SYSVOL folder: %w", err)
	}
	if in.LinkTo != "" {
		if err := setLink(s, in.LinkTo, guid, 0, true); err != nil {
			return map[string]any{"guid": guid, "warning": "GPO created but not linked: " + err.Error()}, nil
		}
	}
	return map[string]any{"guid": guid}, nil
}

func apiGPODelete(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID string `json:"guid"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, err := normGUID(in.GUID)
	if err != nil {
		return nil, err
	}
	// The two built-in GPOs are required by a domain.
	if guid == "{31B2F340-016D-11D2-945F-00C04FB984F9}" || guid == "{6AC1786C-016F-11D2-945F-00C04FB984F9}" {
		return nil, errors.New("the Default Domain Policy and Default Domain Controllers Policy cannot be deleted")
	}
	dn := gpoDN(s, guid)
	removed := 0
	err = s.With(func(c *Conn) error {
		if _, err := c.Read(dn, []string{"name"}); err != nil {
			return err
		}
		for _, base := range []string{s.base, "CN=Sites," + s.config} {
			les, _, err := c.Search(base, ScopeSub, "(gPLink=*)", []string{"gPLink"}, 5000)
			if err != nil {
				continue
			}
			for _, le := range les {
				links := parseGPLink(le.Get("gPLink"))
				var keep []glink
				for _, l := range links {
					if l.guid() != guid {
						keep = append(keep, l)
					}
				}
				if len(keep) != len(links) {
					if err := writeGPLink(c, le.DN, keep); err != nil {
						return fmt.Errorf("unlinking from %s: %w", le.DN, err)
					}
					removed++
				}
			}
		}
		return c.Delete(dn, true)
	})
	if err != nil {
		return nil, err
	}
	out := map[string]any{"unlinked": removed}
	if err := removeGPOFiles(s, guid); err != nil {
		out["warning"] = "GPO deleted, but its SYSVOL folder could not be removed: " + err.Error()
	}
	return out, nil
}

func apiGPORename(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID string `json:"guid"`
		Name string `json:"name"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, err := normGUID(in.GUID)
	if err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 200 || strings.ContainsAny(in.Name, "\x00\r\n") {
		return nil, errors.New("a name is required")
	}
	return nil, s.With(func(c *Conn) error {
		if es, _, err := c.Search(policiesDN(s), ScopeOne, "(displayName="+EscapeFilter(in.Name)+")", []string{"name"}, 2); err == nil {
			for _, e := range es {
				if !strings.EqualFold(linkGUID(e.DN), guid) {
					return errors.New("a GPO with that name already exists")
				}
			}
		}
		return c.Modify(gpoDN(s, guid), []Mod{{Op: 2, Attr: "displayName", Vals: sv(in.Name)}})
	})
}

func apiGPOStatus(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID  string `json:"guid"`
		Flags int    `json:"flags"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, err := normGUID(in.GUID)
	if err != nil {
		return nil, err
	}
	if in.Flags < 0 || in.Flags > 3 {
		return nil, errors.New("status must be 0 to 3")
	}
	return nil, s.With(func(c *Conn) error {
		return c.Modify(gpoDN(s, guid), []Mod{{Op: 2, Attr: "flags", Vals: sv(strconv.Itoa(in.Flags))}})
	})
}

var extRe = regexp.MustCompile(`^(\[(\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\})+\])*$`)

// apiGPOExt sets the client-side extension lists, which tell clients which kinds of settings the GPO contains.
func apiGPOExt(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID    string `json:"guid"`
		Machine string `json:"machine"`
		User    string `json:"user"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, err := normGUID(in.GUID)
	if err != nil {
		return nil, err
	}
	in.Machine, in.User = strings.TrimSpace(in.Machine), strings.TrimSpace(in.User)
	if !extRe.MatchString(in.Machine) || !extRe.MatchString(in.User) {
		return nil, errors.New(`extension lists look like [{GUID}{GUID}][{GUID}{GUID}]`)
	}
	var mods []Mod
	for _, x := range [][2]string{{"gPCMachineExtensionNames", in.Machine}, {"gPCUserExtensionNames", in.User}} {
		if x[1] == "" {
			mods = append(mods, Mod{Op: 2, Attr: x[0]})
		} else {
			mods = append(mods, Mod{Op: 2, Attr: x[0], Vals: sv(x[1])})
		}
	}
	return nil, s.With(func(c *Conn) error { return c.Modify(gpoDN(s, guid), mods) })
}

// ---------- links ----------

func writeGPLink(c *Conn, target string, links []glink) error {
	if len(links) == 0 {
		return c.Modify(target, []Mod{{Op: 2, Attr: "gPLink"}})
	}
	return c.Modify(target, []Mod{{Op: 2, Attr: "gPLink", Vals: sv(formatGPLink(links))}})
}

func checkLinkTarget(c *Conn, s *Session, target string) (*Entry, error) {
	if err := requireIn(s, target); err != nil {
		return nil, err
	}
	e, err := c.Read(target, []string{"gPLink", "gPOptions", "objectClass"})
	if err != nil {
		return nil, err
	}
	switch kindOfTarget(e.Strs("objectClass")) {
	case "domain", "ou", "site":
		return e, nil
	}
	return nil, errors.New("GPOs can only be linked to the domain, an OU or a site")
}

// setLink adds a link (lowest precedence, i.e. first in the attribute) or updates an existing one's options.
func setLink(s *Session, target, guid string, opt int, onlyIfNew bool) error {
	return s.With(func(c *Conn) error {
		e, err := checkLinkTarget(c, s, target)
		if err != nil {
			return err
		}
		if _, err := c.Read(gpoDN(s, guid), []string{"name"}); err != nil {
			return fmt.Errorf("GPO: %w", err)
		}
		links := parseGPLink(e.Get("gPLink"))
		for i := range links {
			if links[i].guid() == guid {
				if onlyIfNew {
					return nil
				}
				links[i].Opt = opt
				return writeGPLink(c, target, links)
			}
		}
		links = append([]glink{{DN: gpoDN(s, guid), Opt: opt}}, links...)
		return writeGPLink(c, target, links)
	})
}

func apiGPOLink(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID     string `json:"guid"`
		Target   string `json:"target"`
		Enforced bool   `json:"enforced"`
		Disabled bool   `json:"disabled"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, err := normGUID(in.GUID)
	if err != nil {
		return nil, err
	}
	opt := 0
	if in.Disabled {
		opt |= 1
	}
	if in.Enforced {
		opt |= 2
	}
	return nil, setLink(s, in.Target, guid, opt, false)
}

func apiGPOUnlink(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID   string `json:"guid"`
		Target string `json:"target"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, err := normGUID(in.GUID)
	if err != nil {
		return nil, err
	}
	return nil, s.With(func(c *Conn) error {
		e, err := checkLinkTarget(c, s, in.Target)
		if err != nil {
			return err
		}
		var keep []glink
		for _, l := range parseGPLink(e.Get("gPLink")) {
			if l.guid() != guid {
				keep = append(keep, l)
			}
		}
		return writeGPLink(c, in.Target, keep)
	})
}

// apiGPOMove changes a link's precedence: delta -1 = towards link order 1 (higher precedence), +1 = away from it.
func apiGPOMove(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		GUID   string `json:"guid"`
		Target string `json:"target"`
		Delta  int    `json:"delta"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	guid, err := normGUID(in.GUID)
	if err != nil {
		return nil, err
	}
	if in.Delta != -1 && in.Delta != 1 {
		return nil, errors.New("delta must be -1 or 1")
	}
	return nil, s.With(func(c *Conn) error {
		e, err := checkLinkTarget(c, s, in.Target)
		if err != nil {
			return err
		}
		links := parseGPLink(e.Get("gPLink"))
		i := -1
		for k, l := range links {
			if l.guid() == guid {
				i = k
			}
		}
		if i < 0 {
			return errors.New("that GPO is not linked here")
		}
		// attribute order is the reverse of link order: moving to a lower link order number moves it later in the list
		j := i - in.Delta
		if j < 0 || j >= len(links) {
			return nil
		}
		links[i], links[j] = links[j], links[i]
		return writeGPLink(c, in.Target, links)
	})
}

func apiGPOInherit(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		Target string `json:"target"`
		Block  bool   `json:"block"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	return nil, s.With(func(c *Conn) error {
		e, err := checkLinkTarget(c, s, in.Target)
		if err != nil {
			return err
		}
		v := atoi64(e.Get("gPOptions")) &^ 1
		if in.Block {
			v |= 1
		}
		return c.Modify(in.Target, []Mod{{Op: 2, Attr: "gPOptions", Vals: sv(strconv.FormatInt(v, 10))}})
	})
}

// ---------- version and extension bookkeeping ----------

var extGroupRe = regexp.MustCompile(`\[((?:\{[0-9A-Fa-f-]{36}\})+)\]`)

// mergeExt adds tool GUID `tool` to the group for extension `cse` (creating it), keeping Windows' ordering.
func mergeExt(existing, cse, tool string) string {
	type grp struct {
		cse   string
		tools []string
	}
	var groups []*grp
	split := func(s string) []string {
		var out []string
		for _, p := range strings.Split(s, "}") {
			if p != "" {
				out = append(out, strings.ToUpper(p+"}"))
			}
		}
		return out
	}
	for _, m := range extGroupRe.FindAllStringSubmatch(existing, -1) {
		g := split(m[1])
		groups = append(groups, &grp{cse: g[0], tools: g[1:]})
	}
	cse, tool = strings.ToUpper(cse), strings.ToUpper(tool)
	var cur *grp
	for _, g := range groups {
		if g.cse == cse {
			cur = g
		}
	}
	if cur == nil {
		cur = &grp{cse: cse}
		groups = append(groups, cur)
	}
	found := false
	for _, t := range cur.tools {
		found = found || t == tool
	}
	if !found {
		cur.tools = append(cur.tools, tool)
		sort.Strings(cur.tools)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].cse < groups[j].cse })
	var sb strings.Builder
	for _, g := range groups {
		sb.WriteString("[" + g.cse + strings.Join(g.tools, "") + "]")
	}
	return sb.String()
}

// cseRef is a client-side extension (and its tool extension) a GPO must advertise; user selects the user list.
type cseRef struct {
	cse, tool string
	user      bool
}

var (
	cseRegistry     = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
	cseRegistryMach = cseRef{cseRegistry, "{D02B1F72-3407-48AE-BA88-E8213C6761F1}", false}
	cseRegistryUser = cseRef{cseRegistry, "{D02B1F73-3407-48AE-BA88-E8213C6761F1}", true}
	cseSecurity     = cseRef{"{827D319E-6EAC-11D2-A4EA-00C04F79F83A}", "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}", false}
)

// gpoCommit is the one way settings reach SYSVOL. prepare validates everything (paths, etags, content) and returns the
// function that does the write, so a request that would be refused never changes anything. Then an LDAP modify of
// versionNumber (and the extension list) runs as the signed-in user: it is both the version bump clients rely on and the
// permission check, so a user who may not edit the GPO in AD never gets as far as writing a file. Then the write runs,
// and GPT.INI follows the new version.
func gpoCommit(s *Session, guid string, machine, user bool, ext []cseRef, prepare func(dir string) (func() error, error)) error {
	dir, err := gpoDir(s, guid)
	if err != nil {
		return err
	}
	if !sysvolInfo(s).Writable {
		return errors.New("SYSVOL is not writable by goaduc (it has to run as root on the domain controller)")
	}
	write, err := prepare(dir)
	if err != nil {
		return err
	}
	var ver int64
	err = s.With(func(c *Conn) error {
		e, err := c.Read(gpoDN(s, guid), []string{"versionNumber", "gPCMachineExtensionNames", "gPCUserExtensionNames"})
		if err != nil {
			return err
		}
		ver = atoi64(e.Get("versionNumber"))
		lo, hi := ver&0xffff, ver>>16&0xffff
		if machine {
			lo = (lo + 1) & 0xffff
		}
		if user {
			hi = (hi + 1) & 0xffff
		}
		ver = hi<<16 | lo
		mods := []Mod{{Op: 2, Attr: "versionNumber", Vals: sv(strconv.FormatInt(ver, 10))}}
		mext, uext := e.Get("gPCMachineExtensionNames"), e.Get("gPCUserExtensionNames")
		nm, nu := mext, uext
		for _, x := range ext {
			if x.user {
				nu = mergeExt(nu, x.cse, x.tool)
			} else {
				nm = mergeExt(nm, x.cse, x.tool)
			}
		}
		if nm != mext {
			mods = append(mods, Mod{Op: 2, Attr: "gPCMachineExtensionNames", Vals: sv(nm)})
		}
		if nu != uext {
			mods = append(mods, Mod{Op: 2, Attr: "gPCUserExtensionNames", Vals: sv(nu)})
		}
		return c.Modify(gpoDN(s, guid), mods)
	})
	if err != nil {
		return err
	}
	werr := write()
	if gerr := writeGPTVersion(dir, ver); gerr != nil && werr == nil {
		werr = gerr
	}
	return werr
}
