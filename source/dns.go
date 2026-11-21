package main

// DNS Manager for Samba AD DNS. Zones/records live in LDAP (dnsZone/dnsNode
// objects); each dnsNode holds one dnsRecord value per record, in the binary
// DNS_RPC_RECORD layout from MS-DNSP section 2.2.2.2.

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

const (
	dnsA     = 1
	dnsNS    = 2
	dnsCNAME = 5
	dnsSOA   = 6
	dnsPTR   = 12
	dnsMX    = 15
	dnsTXT   = 16
	dnsAAAA  = 28
	dnsSRV   = 33
)

var dnsTypeNames = map[int]string{dnsA: "A", dnsNS: "NS", dnsCNAME: "CNAME", dnsSOA: "SOA", dnsPTR: "PTR", dnsMX: "MX", dnsTXT: "TXT", dnsAAAA: "AAAA", dnsSRV: "SRV"}

func dnsTypeByName(n string) int {
	for k, v := range dnsTypeNames {
		if strings.EqualFold(v, n) {
			return k
		}
	}
	return 0
}

type DNSRec struct {
	Raw       string         `json:"raw"` // base64 of the exact stored value (used to address it for edit/delete)
	Type      string         `json:"type"`
	TTL       uint32         `json:"ttl"`
	Serial    uint32         `json:"serial"`
	Dynamic   bool           `json:"dynamic"` // registered dynamically (has an aging timestamp)
	Timestamp string         `json:"timestamp,omitempty"`
	Text      string         `json:"text"`
	Fields    map[string]any `json:"fields"`
	Editable  bool           `json:"editable"`
}

// ---- DNS_COUNT_NAME ----

func encodeCountName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	var raw []byte
	n := 0
	if name != "" {
		if len(name) > 253 {
			return nil, errors.New("name too long")
		}
		for _, l := range strings.Split(name, ".") {
			if l == "" || len(l) > 63 {
				return nil, fmt.Errorf("invalid DNS name %q", name)
			}
			raw = append(raw, byte(len(l)))
			raw = append(raw, l...)
			n++
		}
	}
	raw = append(raw, 0)
	return append([]byte{byte(len(raw)), byte(n)}, raw...), nil
}

func parseCountName(d []byte) (string, int, error) {
	if len(d) < 2 || len(d) < 2+int(d[0]) || d[0] == 0 {
		return "", 0, errors.New("bad DNS name")
	}
	raw := d[2 : 2+int(d[0])]
	var labels []string
	for i := 0; i < len(raw); {
		l := int(raw[i])
		if l == 0 {
			break
		}
		if i+1+l > len(raw) {
			return "", 0, errors.New("bad DNS label")
		}
		labels = append(labels, string(raw[i+1:i+1+l]))
		i += 1 + l
	}
	if len(labels) == 0 {
		return ".", 2 + int(d[0]), nil
	}
	return strings.Join(labels, ".") + ".", 2 + int(d[0]), nil
}

// ---- helpers to read JSON field maps ----

func fStr(f map[string]any, k string) string {
	switch v := f[k].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func fUint(f map[string]any, k string, max uint64) (uint64, error) {
	s := fStr(f, k)
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n > max {
		return 0, fmt.Errorf("%s must be a number between 0 and %d", k, max)
	}
	return n, nil
}

func be16(v uint64) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, uint16(v)); return b }
func be32(v uint64) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, uint32(v)); return b }

// encodeDNSRecord builds a static (non-aging) record value.
func encodeDNSRecord(typ string, fields map[string]any, ttl uint32, serial uint32) ([]byte, error) {
	t := dnsTypeByName(typ)
	var data []byte
	switch t {
	case dnsA:
		ip := net.ParseIP(fStr(fields, "address"))
		if ip == nil || ip.To4() == nil {
			return nil, errors.New("invalid IPv4 address")
		}
		data = ip.To4()
	case dnsAAAA:
		ip := net.ParseIP(fStr(fields, "address"))
		if ip == nil || ip.To4() != nil {
			return nil, errors.New("invalid IPv6 address")
		}
		data = ip.To16()
	case dnsNS, dnsCNAME, dnsPTR:
		n, err := encodeCountName(fStr(fields, "target"))
		if err != nil || fStr(fields, "target") == "" {
			return nil, errors.New("a target host name is required")
		}
		data = n
	case dnsMX:
		p, err := fUint(fields, "preference", 65535)
		if err != nil {
			return nil, err
		}
		n, err := encodeCountName(fStr(fields, "target"))
		if err != nil || fStr(fields, "target") == "" {
			return nil, errors.New("a mail server name is required")
		}
		data = append(be16(p), n...)
	case dnsSRV:
		pr, err := fUint(fields, "priority", 65535)
		if err != nil {
			return nil, err
		}
		w, err := fUint(fields, "weight", 65535)
		if err != nil {
			return nil, err
		}
		po, err := fUint(fields, "port", 65535)
		if err != nil {
			return nil, err
		}
		n, err := encodeCountName(fStr(fields, "target"))
		if err != nil || fStr(fields, "target") == "" {
			return nil, errors.New("a target host name is required")
		}
		data = cat(be16(pr), be16(w), be16(po), n)
	case dnsTXT:
		txt, _ := fields["text"].(string)
		if txt == "" {
			return nil, errors.New("text is required")
		}
		for b := []byte(txt); len(b) > 0; {
			n := len(b)
			if n > 255 {
				n = 255
			}
			data = append(data, byte(n))
			data = append(data, b[:n]...)
			b = b[n:]
		}
	case dnsSOA:
		var nums [5]uint64
		for i, k := range []string{"serial", "refresh", "retry", "expire", "minimum"} {
			v, err := fUint(fields, k, 0xFFFFFFFF)
			if err != nil {
				return nil, err
			}
			nums[i] = v
		}
		p, err := encodeCountName(fStr(fields, "primary"))
		if err != nil || fStr(fields, "primary") == "" {
			return nil, errors.New("primary name server is required")
		}
		a, err := encodeCountName(fStr(fields, "admin"))
		if err != nil || fStr(fields, "admin") == "" {
			return nil, errors.New("responsible person is required")
		}
		data = cat(be32(nums[0]), be32(nums[1]), be32(nums[2]), be32(nums[3]), be32(nums[4]), p, a)
	default:
		return nil, fmt.Errorf("record type %q is not supported", typ)
	}
	h := make([]byte, 24)
	binary.LittleEndian.PutUint16(h[0:], uint16(len(data)))
	binary.LittleEndian.PutUint16(h[2:], uint16(t))
	h[4] = 5   // version
	h[5] = 240 // rank: zone data
	binary.LittleEndian.PutUint32(h[8:], serial)
	binary.BigEndian.PutUint32(h[12:], ttl)
	return append(h, data...), nil
}

func decodeDNSRecord(b []byte) (*DNSRec, int, error) {
	if len(b) < 24 {
		return nil, 0, errors.New("short dnsRecord")
	}
	dl := int(binary.LittleEndian.Uint16(b[0:]))
	t := int(binary.LittleEndian.Uint16(b[2:]))
	if len(b) < 24+dl {
		return nil, 0, errors.New("truncated dnsRecord")
	}
	data := b[24 : 24+dl]
	r := &DNSRec{Raw: base64.StdEncoding.EncodeToString(b), Serial: binary.LittleEndian.Uint32(b[8:]), TTL: binary.BigEndian.Uint32(b[12:]), Fields: map[string]any{}, Editable: true}
	if ts := binary.LittleEndian.Uint32(b[20:]); ts != 0 {
		r.Dynamic = true
		r.Timestamp = fileTime(strconv.FormatInt(int64(ts)*3600*10000000, 10)) // hours since 1601
	}
	if n, ok := dnsTypeNames[t]; ok {
		r.Type = n
	} else {
		r.Type = "TYPE" + strconv.Itoa(t)
	}
	bad := func() (*DNSRec, int, error) { return nil, t, errors.New("malformed record data") }
	switch t {
	case dnsA:
		if len(data) != 4 {
			return bad()
		}
		r.Fields["address"] = net.IP(data).String()
		r.Text = net.IP(data).String()
	case dnsAAAA:
		if len(data) != 16 {
			return bad()
		}
		r.Fields["address"] = net.IP(data).String()
		r.Text = net.IP(data).String()
	case dnsNS, dnsCNAME, dnsPTR:
		n, _, err := parseCountName(data)
		if err != nil {
			return bad()
		}
		r.Fields["target"] = n
		r.Text = n
	case dnsMX:
		if len(data) < 4 {
			return bad()
		}
		n, _, err := parseCountName(data[2:])
		if err != nil {
			return bad()
		}
		p := binary.BigEndian.Uint16(data)
		r.Fields["preference"], r.Fields["target"] = p, n
		r.Text = fmt.Sprintf("[%d] %s", p, n)
	case dnsSRV:
		if len(data) < 8 {
			return bad()
		}
		n, _, err := parseCountName(data[6:])
		if err != nil {
			return bad()
		}
		pr, w, po := binary.BigEndian.Uint16(data), binary.BigEndian.Uint16(data[2:]), binary.BigEndian.Uint16(data[4:])
		r.Fields["priority"], r.Fields["weight"], r.Fields["port"], r.Fields["target"] = pr, w, po, n
		r.Text = fmt.Sprintf("[%d][%d][%d] %s", pr, w, po, n)
	case dnsTXT:
		var sb strings.Builder
		for i := 0; i < len(data); {
			l := int(data[i])
			if i+1+l > len(data) {
				return bad()
			}
			sb.Write(data[i+1 : i+1+l])
			i += 1 + l
		}
		r.Fields["text"] = sb.String()
		r.Text = sb.String()
	case dnsSOA:
		if len(data) < 22 {
			return bad()
		}
		pn, used, err := parseCountName(data[20:])
		if err != nil {
			return bad()
		}
		an, _, err := parseCountName(data[20+used:])
		if err != nil {
			return bad()
		}
		f := r.Fields
		f["serial"], f["refresh"], f["retry"], f["expire"], f["minimum"] = binary.BigEndian.Uint32(data), binary.BigEndian.Uint32(data[4:]), binary.BigEndian.Uint32(data[8:]), binary.BigEndian.Uint32(data[12:]), binary.BigEndian.Uint32(data[16:])
		f["primary"], f["admin"] = pn, an
		r.Text = fmt.Sprintf("[%d] %s %s", f["serial"], pn, an)
	case 0:
		return nil, 0, nil // tombstone
	default:
		r.Editable = false
		r.Text = fmt.Sprintf("(%d bytes) %s", len(data), hex.EncodeToString(data))
	}
	return r, t, nil
}

// bumpSOASerial increments the zone's SOA serial (best effort).
func bumpSOASerial(c *Conn, zone string) {
	apex := "DC=@," + zone
	e, err := c.Read(apex, []string{"dnsRecord"})
	if err != nil {
		return
	}
	for _, v := range e.Attrs["dnsRecord"] {
		if len(v) < 24+4 || binary.LittleEndian.Uint16(v[2:]) != dnsSOA {
			continue
		}
		nv := append([]byte(nil), v...)
		serial := binary.BigEndian.Uint32(nv[24:]) + 1
		binary.BigEndian.PutUint32(nv[24:], serial)
		binary.LittleEndian.PutUint32(nv[8:], serial)
		c.Modify(apex, []Mod{{Op: 1, Attr: "dnsRecord", Vals: [][]byte{v}}, {Op: 0, Attr: "dnsRecord", Vals: [][]byte{nv}}})
		return
	}
}

func zoneSerial(c *Conn, zone string) uint32 {
	e, err := c.Read("DC=@,"+zone, []string{"dnsRecord"})
	if err != nil {
		return 1
	}
	for _, v := range e.Attrs["dnsRecord"] {
		if len(v) >= 28 && binary.LittleEndian.Uint16(v[2:]) == dnsSOA {
			return binary.BigEndian.Uint32(v[24:])
		}
	}
	return 1
}

// ---- zones ----

func (s *Session) dnsContainers() map[string]string { // container DN -> scope label
	m := map[string]string{
		"CN=MicrosoftDNS,DC=DomainDnsZones," + s.base: "Domain",
		"CN=MicrosoftDNS,DC=ForestDnsZones," + s.root: "Forest",
		"CN=MicrosoftDNS,CN=System," + s.base:         "Legacy",
	}
	return m
}

func dnsZoneOK(s *Session, dn string) bool {
	for c := range s.dnsContainers() {
		if strings.EqualFold(parentDN(dn), c) {
			return true
		}
	}
	return false
}

func apiDNSZones(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	type zone struct {
		Name    string `json:"name"`
		DN      string `json:"dn"`
		Scope   string `json:"scope"`
		Reverse bool   `json:"reverse"`
	}
	zones := []zone{}
	err := s.With(func(c *Conn) error {
		for cont, scope := range s.dnsContainers() {
			es, _, err := c.Search(cont, ScopeOne, "(objectClass=dnsZone)", []string{"dc"}, 1000)
			if err != nil {
				var le *LDAPError
				if errors.As(err, &le) && (le.Code == 32 || le.Code == 50) {
					continue
				}
				return err
			}
			for _, e := range es {
				n := dnLabel(e.DN, 0)
				if n == "RootDNSServers" || strings.HasPrefix(n, "..") || n == "TrustAnchors" {
					continue
				}
				zones = append(zones, zone{n, e.DN, scope, strings.HasSuffix(strings.ToLower(n), ".arpa")})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(zones, func(i, j int) bool {
		if zones[i].Reverse != zones[j].Reverse {
			return !zones[i].Reverse
		}
		return strings.ToLower(zones[i].Name) < strings.ToLower(zones[j].Name)
	})
	return map[string]any{"zones": zones}, nil
}

func apiDNSRecords(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	zone := r.URL.Query().Get("zone")
	if !dnsZoneOK(s, zone) {
		return nil, errors.New("not a DNS zone")
	}
	type row struct {
		Name string    `json:"name"`
		Recs []*DNSRec `json:"records"`
	}
	rows := []row{}
	trunc := false
	err := s.With(func(c *Conn) error {
		es, t, err := c.Search(zone, ScopeOne, "(objectClass=dnsNode)", []string{"dnsRecord", "dNSTombstoned"}, 5000)
		trunc = t
		if err != nil {
			return err
		}
		for _, e := range es {
			var recs []*DNSRec
			for _, v := range e.Attrs["dnsRecord"] {
				rec, _, err := decodeDNSRecord(v)
				if err != nil {
					rec = &DNSRec{Raw: base64.StdEncoding.EncodeToString(v), Type: "?", Text: "(unreadable record: " + err.Error() + ")", Fields: map[string]any{}}
				}
				if rec != nil {
					recs = append(recs, rec)
				}
			}
			if len(recs) > 0 {
				rows = append(rows, row{dnLabel(e.DN, 0), recs})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(rows, func(i, j int) bool {
		if (rows[i].Name == "@") != (rows[j].Name == "@") {
			return rows[i].Name == "@"
		}
		return strings.ToLower(rows[i].Name) < strings.ToLower(rows[j].Name)
	})
	return map[string]any{"nodes": rows, "truncated": trunc}, nil
}

type dnsReq struct {
	Zone   string         `json:"zone"`
	Name   string         `json:"name"`
	Old    string         `json:"old"` // base64 of the record being replaced/removed
	Type   string         `json:"type"`
	TTL    uint32         `json:"ttl"`
	Fields map[string]any `json:"fields"`
}

func dnsApply(s *Session, in dnsReq, del bool) error {
	if !dnsZoneOK(s, in.Zone) {
		return errors.New("not a DNS zone")
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return errors.New("record name is required (use @ for the zone apex)")
	}
	for _, ch := range in.Name {
		if ch < 0x20 || ch == '/' || ch == ' ' {
			return errors.New("invalid characters in record name")
		}
	}
	var old []byte
	if in.Old != "" {
		var err error
		if old, err = base64.StdEncoding.DecodeString(in.Old); err != nil {
			return errors.New("bad record reference")
		}
	}
	if del && old == nil {
		return errors.New("nothing to delete")
	}
	nodeDN := "DC=" + escapeRDN(in.Name) + "," + in.Zone
	return s.With(func(c *Conn) error {
		var nb []byte
		if !del {
			if in.TTL > 2147483647 {
				return errors.New("TTL out of range")
			}
			if in.TTL == 0 {
				in.TTL = 3600
			}
			var err error
			nb, err = encodeDNSRecord(in.Type, in.Fields, in.TTL, zoneSerial(c, in.Zone)+1)
			if err != nil {
				return err
			}
		}
		e, err := c.Read(nodeDN, []string{"dnsRecord"})
		var le *LDAPError
		if err != nil && !(errors.As(err, &le) && le.Code == 32) {
			return err
		}
		if err != nil { // no such node yet
			if del {
				return errors.New("record not found")
			}
			if err := c.Add(nodeDN, []Mod{{Attr: "objectClass", Vals: svs([]string{"top", "dnsNode"})}, {Attr: "dc", Vals: sv(in.Name)}, {Attr: "dnsRecord", Vals: [][]byte{nb}}}); err != nil {
				return err
			}
			bumpSOASerial(c, in.Zone)
			return nil
		}
		cur := e.Attrs["dnsRecord"]
		if old != nil {
			found := false
			for _, v := range cur {
				found = found || string(v) == string(old)
			}
			if !found {
				return errors.New("the record changed since it was loaded; refresh and try again")
			}
		}
		// CNAME exclusivity
		var remaining []int
		for _, v := range cur {
			if old != nil && string(v) == string(old) {
				continue
			}
			if len(v) >= 4 {
				if t := int(binary.LittleEndian.Uint16(v[2:])); t != 0 {
					remaining = append(remaining, t)
				}
			}
		}
		if !del {
			nt := dnsTypeByName(in.Type)
			for _, t := range remaining {
				if (nt == dnsCNAME && t != 0) || t == dnsCNAME {
					return errors.New("a name with a CNAME record cannot have other records")
				}
			}
		}
		var mods []Mod
		if old != nil {
			mods = append(mods, Mod{Op: 1, Attr: "dnsRecord", Vals: [][]byte{old}})
		}
		if !del {
			mods = append(mods, Mod{Op: 0, Attr: "dnsRecord", Vals: [][]byte{nb}})
		}
		if err := c.Modify(nodeDN, mods); err != nil {
			return err
		}
		if del {
			e := dnsBinEntry{Zone: in.Zone, ZoneName: dnLabel(in.Zone, 0), Name: in.Name, By: s.user}
			if rec, _, derr := decodeDNSRecord(old); derr == nil && rec != nil {
				e.Type, e.TTL, e.Text, e.Fields, e.Restorable = rec.Type, rec.TTL, rec.Text, rec.Fields, rec.Editable
			} else {
				e.Type, e.Text = "?", "(unreadable record)"
			}
			dnsBinAdd(e)
		}
		if del && len(remaining) == 0 && in.Name != "@" {
			c.Delete(nodeDN, false) // last record gone: remove the empty node
		}
		if !(in.Name == "@" && in.Type == "SOA") {
			bumpSOASerial(c, in.Zone)
		}
		return nil
	})
}

func apiDNSSave(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in dnsReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	return nil, dnsApply(s, in, false)
}

func apiDNSDelete(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in dnsReq
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	return nil, dnsApply(s, in, true)
}
