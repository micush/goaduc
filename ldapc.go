package main

// Minimal LDAPv3 client (stdlib only): enough for Active Directory / Samba 4
// administration. Supports simple bind, StartTLS/LDAPS, search (with paged
// results), add, modify, delete, modifyDN, and RFC 4515 filter parsing.

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---------- BER helpers ----------

func berLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for x := n; x > 0; x >>= 8 {
		b = append([]byte{byte(x)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func enc(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, berLen(len(content))...)
	return append(out, content...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func bOctet(s string) []byte  { return enc(0x04, []byte(s)) }
func bOctetB(b []byte) []byte { return enc(0x04, b) }
func bEnum(n int) []byte      { return enc(0x0a, intBytes(n)) }
func bInt(n int) []byte       { return enc(0x02, intBytes(n)) }
func bBool(v bool) []byte {
	if v {
		return enc(0x01, []byte{0xff})
	}
	return enc(0x01, []byte{0x00})
}

func intBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var b []byte
	x := n
	for {
		b = append([]byte{byte(x)}, b...)
		x >>= 8
		if (x == 0 && b[0]&0x80 == 0) || (x == -1 && b[0]&0x80 != 0) {
			break
		}
	}
	return b
}

func parseInt(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	n := 0
	if b[0]&0x80 != 0 {
		n = -1
	}
	for _, c := range b {
		n = n<<8 | int(c)
	}
	return n
}

type tlv struct {
	tag byte
	val []byte
}

func readTLV(r *bufio.Reader) (tlv, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return tlv{}, err
	}
	lb, err := r.ReadByte()
	if err != nil {
		return tlv{}, err
	}
	n := int(lb)
	if lb&0x80 != 0 {
		k := int(lb & 0x7f)
		if k == 0 || k > 4 {
			return tlv{}, errors.New("ldap: unsupported BER length")
		}
		n = 0
		for i := 0; i < k; i++ {
			c, err := r.ReadByte()
			if err != nil {
				return tlv{}, err
			}
			n = n<<8 | int(c)
		}
	}
	if n < 0 || n > 256<<20 {
		return tlv{}, errors.New("ldap: message too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return tlv{}, err
	}
	return tlv{tag, buf}, nil
}

func parseAll(b []byte) ([]tlv, error) {
	var out []tlv
	for len(b) > 0 {
		if len(b) < 2 {
			return nil, errors.New("ldap: truncated BER")
		}
		tag := b[0]
		n := int(b[1])
		off := 2
		if n&0x80 != 0 {
			k := n & 0x7f
			if k == 0 || k > 4 || len(b) < 2+k {
				return nil, errors.New("ldap: bad BER length")
			}
			n = 0
			for i := 0; i < k; i++ {
				n = n<<8 | int(b[2+i])
			}
			off = 2 + k
		}
		if n < 0 || len(b) < off+n {
			return nil, errors.New("ldap: truncated BER value")
		}
		out = append(out, tlv{tag, b[off : off+n]})
		b = b[off+n:]
	}
	return out, nil
}

// ---------- Filters (RFC 4515) ----------

func unescapeFilter(s string) ([]byte, error) {
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			if i+2 >= len(s) {
				return nil, errors.New("bad escape in filter")
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return nil, errors.New("bad escape in filter")
			}
			out = append(out, byte(v))
			i += 2
			continue
		}
		out = append(out, s[i])
	}
	return out, nil
}

// EscapeFilter escapes a literal value for use in a filter.
func EscapeFilter(s string) string {
	var sb strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c == '*' || c == '(' || c == ')' || c == '\\' || c == 0 || c >= 0x80:
			fmt.Fprintf(&sb, "\\%02x", c)
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

func ParseFilter(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	f, rest, err := parseFilterAt(s, 0)
	if err != nil {
		return nil, err
	}
	if rest != "" {
		return nil, errors.New("filter: trailing characters")
	}
	return f, nil
}

func parseFilterAt(s string, depth int) ([]byte, string, error) {
	if depth > 32 {
		return nil, "", errors.New("filter: too deeply nested")
	}
	if len(s) < 3 || s[0] != '(' {
		return nil, "", errors.New("filter: expected '('")
	}
	s = s[1:]
	switch s[0] {
	case '&', '|':
		tag := byte(0xa0)
		if s[0] == '|' {
			tag = 0xa1
		}
		s = s[1:]
		var parts []byte
		for len(s) > 0 && s[0] == '(' {
			f, r, err := parseFilterAt(s, depth+1)
			if err != nil {
				return nil, "", err
			}
			parts = append(parts, f...)
			s = r
		}
		if len(s) == 0 || s[0] != ')' {
			return nil, "", errors.New("filter: expected ')'")
		}
		return enc(tag, parts), s[1:], nil
	case '!':
		f, r, err := parseFilterAt(s[1:], depth+1)
		if err != nil {
			return nil, "", err
		}
		if len(r) == 0 || r[0] != ')' {
			return nil, "", errors.New("filter: expected ')'")
		}
		return enc(0xa2, f), r[1:], nil
	}
	i := strings.IndexByte(s, ')')
	if i < 0 {
		return nil, "", errors.New("filter: expected ')'")
	}
	item, rest := s[:i], s[i+1:]
	eq := strings.IndexByte(item, '=')
	if eq <= 0 {
		return nil, "", errors.New("filter: missing '='")
	}
	attr, val := item[:eq], item[eq+1:]
	op := byte(0xa3)
	switch attr[len(attr)-1] {
	case '>':
		op, attr = 0xa5, attr[:len(attr)-1]
	case '<':
		op, attr = 0xa6, attr[:len(attr)-1]
	case '~':
		op, attr = 0xa8, attr[:len(attr)-1]
	case ':':
		// extensible match: attr[:dn][:rule]:=value
		attr = attr[:len(attr)-1]
		parts := strings.Split(attr, ":")
		var typ, rule string
		dn := false
		typ = parts[0]
		for _, p := range parts[1:] {
			if strings.EqualFold(p, "dn") {
				dn = true
			} else {
				rule = p
			}
		}
		v, err := unescapeFilter(val)
		if err != nil {
			return nil, "", err
		}
		var body []byte
		if rule != "" {
			body = append(body, enc(0x81, []byte(rule))...)
		}
		if typ != "" {
			body = append(body, enc(0x82, []byte(typ))...)
		}
		body = append(body, enc(0x83, v)...)
		if dn {
			body = append(body, enc(0x84, []byte{0xff})...)
		}
		return enc(0xa9, body), rest, nil
	}
	if attr == "" {
		return nil, "", errors.New("filter: empty attribute")
	}
	if op == 0xa3 {
		if val == "*" {
			return enc(0x87, []byte(attr)), rest, nil
		}
		if strings.Contains(val, "*") {
			segs := strings.Split(val, "*")
			var subs []byte
			for i, sg := range segs {
				if sg == "" {
					continue
				}
				u, err := unescapeFilter(sg)
				if err != nil {
					return nil, "", err
				}
				switch {
				case i == 0:
					subs = append(subs, enc(0x80, u)...)
				case i == len(segs)-1:
					subs = append(subs, enc(0x82, u)...)
				default:
					subs = append(subs, enc(0x81, u)...)
				}
			}
			return enc(0xa4, cat(bOctet(attr), enc(0x30, subs))), rest, nil
		}
	}
	v, err := unescapeFilter(val)
	if err != nil {
		return nil, "", err
	}
	return enc(op, cat(bOctet(attr), bOctetB(v))), rest, nil
}

// ---------- Errors ----------

type LDAPError struct {
	Code int
	Msg  string
}

func (e *LDAPError) Error() string {
	name := ldapCodeNames[e.Code]
	if name == "" {
		name = "error " + strconv.Itoa(e.Code)
	}
	if e.Msg != "" {
		return "LDAP " + name + ": " + e.Msg
	}
	return "LDAP " + name
}

var ldapCodeNames = map[int]string{
	1: "operationsError", 2: "protocolError", 4: "sizeLimitExceeded", 7: "authMethodNotSupported",
	8: "strongerAuthRequired", 10: "referral", 16: "noSuchAttribute", 17: "undefinedAttributeType",
	19: "constraintViolation", 20: "attributeOrValueExists", 21: "invalidAttributeSyntax",
	32: "noSuchObject", 34: "invalidDNSyntax", 48: "inappropriateAuthentication", 49: "invalidCredentials",
	50: "insufficientAccessRights", 51: "busy", 52: "unavailable", 53: "unwillingToPerform",
	64: "namingViolation", 65: "objectClassViolation", 66: "notAllowedOnNonLeaf", 68: "entryAlreadyExists",
}

// ---------- Connection ----------

type Config struct {
	URL      string
	StartTLS bool
	Insecure bool
	CAFile   string
	Timeout  time.Duration
}

type Conn struct {
	nc    net.Conn
	r     *bufio.Reader
	id    int
	IsTLS bool
}

type Entry struct {
	DN    string
	Attrs map[string][][]byte
}

func (e *Entry) Strs(attr string) []string {
	for k, v := range e.Attrs {
		if strings.EqualFold(k, attr) {
			out := make([]string, len(v))
			for i := range v {
				out[i] = string(v[i])
			}
			return out
		}
	}
	return nil
}

func (e *Entry) Get(attr string) string {
	if v := e.Strs(attr); len(v) > 0 {
		return v[0]
	}
	return ""
}

func Dial(cfg *Config) (*Conn, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	host := u.Host
	scheme := strings.ToLower(u.Scheme)
	if u.Port() == "" {
		if scheme == "ldaps" {
			host = net.JoinHostPort(u.Hostname(), "636")
		} else {
			host = net.JoinHostPort(u.Hostname(), "389")
		}
	}
	tcfg := &tls.Config{ServerName: u.Hostname(), InsecureSkipVerify: cfg.Insecure, MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("no certificates found in CA file")
		}
		tcfg.RootCAs = pool
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	var nc net.Conn
	isTLS := false
	switch scheme {
	case "ldaps":
		nc, err = tls.DialWithDialer(&d, "tcp", host, tcfg)
		isTLS = true
	case "ldap":
		nc, err = d.Dial("tcp", host)
	default:
		return nil, errors.New("server URL must be ldap:// or ldaps://")
	}
	if err != nil {
		return nil, err
	}
	c := &Conn{nc: nc, r: bufio.NewReader(nc), IsTLS: isTLS}
	if scheme == "ldap" && cfg.StartTLS {
		if err := c.startTLS(tcfg); err != nil {
			nc.Close()
			return nil, err
		}
	}
	return c, nil
}

func (c *Conn) Close() {
	c.nc.SetDeadline(time.Now().Add(time.Second))
	c.nc.Write(enc(0x30, cat(bInt(c.nextID()), enc(0x42, nil))))
	c.nc.Close()
}

func (c *Conn) nextID() int { c.id++; return c.id }

func (c *Conn) send(op, controls []byte) (int, error) {
	id := c.nextID()
	msg := cat(bInt(id), op)
	if len(controls) > 0 {
		msg = append(msg, enc(0xa0, controls)...)
	}
	c.nc.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, err := c.nc.Write(enc(0x30, msg))
	return id, err
}

type reply struct {
	op       tlv
	controls []byte
}

func (c *Conn) recv(id int) (*reply, error) {
	for {
		c.nc.SetReadDeadline(time.Now().Add(60 * time.Second))
		m, err := readTLV(c.r)
		if err != nil {
			return nil, err
		}
		kids, err := parseAll(m.val)
		if err != nil || len(kids) < 2 {
			return nil, errors.New("ldap: malformed message")
		}
		if parseInt(kids[0].val) != id {
			continue // e.g. unsolicited notice
		}
		r := &reply{op: kids[1]}
		if len(kids) > 2 && kids[2].tag == 0xa0 {
			r.controls = kids[2].val
		}
		return r, nil
	}
}

func parseResult(v []byte) error {
	k, err := parseAll(v)
	if err != nil || len(k) < 3 {
		return errors.New("ldap: malformed result")
	}
	code := parseInt(k[0].val)
	if code == 0 {
		return nil
	}
	return &LDAPError{Code: code, Msg: string(k[2].val)}
}

// roundTrip handles ops with a single LDAPResult response.
func (c *Conn) roundTrip(op, controls []byte, want byte) error {
	id, err := c.send(op, controls)
	if err != nil {
		return err
	}
	r, err := c.recv(id)
	if err != nil {
		return err
	}
	if r.op.tag != want {
		return fmt.Errorf("ldap: unexpected response 0x%x", r.op.tag)
	}
	return parseResult(r.op.val)
}

func (c *Conn) startTLS(tcfg *tls.Config) error {
	op := enc(0x77, enc(0x80, []byte("1.3.6.1.4.1.1466.20037")))
	if err := c.roundTrip(op, nil, 0x78); err != nil {
		return err
	}
	tc := tls.Client(c.nc, tcfg)
	if err := tc.Handshake(); err != nil {
		return err
	}
	c.nc = tc
	c.r = bufio.NewReader(tc)
	c.IsTLS = true
	return nil
}

func (c *Conn) Bind(name, password string) error {
	if password == "" {
		return &LDAPError{Code: 49, Msg: "empty password not allowed"}
	}
	op := enc(0x60, cat(bInt(3), bOctet(name), enc(0x80, []byte(password))))
	return c.roundTrip(op, nil, 0x61)
}

const (
	ScopeBase = 0
	ScopeOne  = 1
	ScopeSub  = 2
)

const oidPaged = "1.2.840.113556.1.4.319"
const oidShowDeleted = "1.2.840.113556.1.4.417"
const oidTreeDelete = "1.2.840.113556.1.4.805"

func control(oid string, crit bool, val []byte) []byte {
	b := cat(bOctet(oid), bBool(crit))
	if val != nil {
		b = append(b, bOctetB(val)...)
	}
	return enc(0x30, b)
}

// Search runs a search. max==0 means unlimited. truncated is true when the
// size limit was hit.
func (c *Conn) Search(base string, scope int, filter string, attrs []string, max int) ([]*Entry, bool, error) {
	return c.SearchCtl(base, scope, filter, attrs, max, nil)
}

// SearchCtl is Search with extra (pre-encoded) request controls.
func (c *Conn) SearchCtl(base string, scope int, filter string, attrs []string, max int, extra []byte) (entries []*Entry, truncated bool, err error) {
	f, err := ParseFilter(filter)
	if err != nil {
		return nil, false, err
	}
	var attrBytes []byte
	for _, a := range attrs {
		attrBytes = append(attrBytes, bOctet(a)...)
	}
	cookie := []byte{}
	for {
		page := 500
		if max > 0 && max < page {
			page = max
		}
		op := enc(0x63, cat(bOctet(base), bEnum(scope), bEnum(0), bInt(max), bInt(0), bBool(false), f, enc(0x30, attrBytes)))
		ctl := cat(extra, control(oidPaged, false, enc(0x30, cat(bInt(page), bOctetB(cookie)))))
		id, err := c.send(op, ctl)
		if err != nil {
			return nil, false, err
		}
		var next []byte
		for {
			r, err := c.recv(id)
			if err != nil {
				return nil, false, err
			}
			switch r.op.tag {
			case 0x64:
				k, err := parseAll(r.op.val)
				if err != nil || len(k) < 2 {
					return nil, false, errors.New("ldap: bad entry")
				}
				e := &Entry{DN: string(k[0].val), Attrs: map[string][][]byte{}}
				al, _ := parseAll(k[1].val)
				for _, a := range al {
					p, _ := parseAll(a.val)
					if len(p) < 2 {
						continue
					}
					vs, _ := parseAll(p[1].val)
					var vals [][]byte
					for _, v := range vs {
						vals = append(vals, v.val)
					}
					e.Attrs[string(p[0].val)] = vals
				}
				entries = append(entries, e)
			case 0x73: // referral, ignore
			case 0x65:
				if err := parseResult(r.op.val); err != nil {
					var le *LDAPError
					if errors.As(err, &le) && le.Code == 4 {
						truncated = true
					} else {
						return nil, false, err
					}
				}
				next = pagedCookie(r.controls)
				goto done
			default:
				return nil, false, fmt.Errorf("ldap: unexpected search response 0x%x", r.op.tag)
			}
		}
	done:
		if truncated || len(next) == 0 {
			return entries, truncated, nil
		}
		if max > 0 && len(entries) >= max {
			return entries, true, nil
		}
		cookie = next
	}
}

func pagedCookie(ctrls []byte) []byte {
	cs, _ := parseAll(ctrls)
	for _, c := range cs {
		k, _ := parseAll(c.val)
		if len(k) >= 2 && string(k[0].val) == oidPaged {
			v := k[len(k)-1].val
			s, _ := parseAll(v)
			if len(s) == 1 {
				p, _ := parseAll(s[0].val)
				if len(p) >= 2 {
					return p[1].val
				}
			}
		}
	}
	return nil
}

// SearchOne reads a single object by DN. Returns nil if not found.
func (c *Conn) Read(dn string, attrs []string) (*Entry, error) {
	es, _, err := c.Search(dn, ScopeBase, "(objectClass=*)", attrs, 1)
	if err != nil {
		return nil, err
	}
	if len(es) == 0 {
		return nil, &LDAPError{Code: 32, Msg: "no such object"}
	}
	return es[0], nil
}

type Mod struct {
	Op   int // 0 add, 1 delete, 2 replace
	Attr string
	Vals [][]byte
}

func partial(attr string, vals [][]byte) []byte {
	var vs []byte
	for _, v := range vals {
		vs = append(vs, bOctetB(v)...)
	}
	return cat(bOctet(attr), enc(0x31, vs))
}

func (c *Conn) Modify(dn string, mods []Mod) error { return c.ModifyCtl(dn, mods, nil) }

func (c *Conn) ModifyCtl(dn string, mods []Mod, ctl []byte) error {
	var ml []byte
	for _, m := range mods {
		ml = append(ml, enc(0x30, cat(bEnum(m.Op), enc(0x30, partial(m.Attr, m.Vals))))...)
	}
	return c.roundTrip(enc(0x66, cat(bOctet(dn), enc(0x30, ml))), ctl, 0x67)
}

func (c *Conn) Add(dn string, attrs []Mod) error {
	var al []byte
	for _, a := range attrs {
		al = append(al, enc(0x30, partial(a.Attr, a.Vals))...)
	}
	return c.roundTrip(enc(0x68, cat(bOctet(dn), enc(0x30, al))), nil, 0x69)
}

func (c *Conn) Delete(dn string, tree bool) error {
	var ctl []byte
	if tree {
		ctl = control(oidTreeDelete, true, nil)
	}
	return c.roundTrip(enc(0x4a, []byte(dn)), ctl, 0x6b)
}

// DeleteDeleted removes an object that is already in Deleted Objects (the show-deleted control makes it visible).
func (c *Conn) DeleteDeleted(dn string) error {
	return c.roundTrip(enc(0x4a, []byte(dn)), control(oidShowDeleted, true, nil), 0x6b)
}

func (c *Conn) ModifyDN(dn, newRDN, newSuperior string) error {
	b := cat(bOctet(dn), bOctet(newRDN), bBool(true))
	if newSuperior != "" {
		b = append(b, enc(0x80, []byte(newSuperior))...)
	}
	return c.roundTrip(enc(0x6c, b), nil, 0x6d)
}
