package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// The DNS side of the Recycle Bin. A DNS record is a value of the dnsRecord attribute of a dnsNode, so deleting one is an
// attribute change and the AD Recycle Bin (which keeps whole deleted objects) never sees it. goaduc therefore keeps its own
// list of the records deleted through the DNS page, in the data directory, and shows it on the Recycle Bin page next to the
// AD objects. Records deleted by other tools (samba-tool, DNS Manager) are not in it.

const maxDNSBin = 2000

type dnsBinEntry struct {
	ID         string         `json:"id"`
	Zone       string         `json:"zone"`     // zone DN
	ZoneName   string         `json:"zoneName"` // for display
	Name       string         `json:"name"`
	Type       string         `json:"type"`
	TTL        uint32         `json:"ttl"`
	Text       string         `json:"text"`
	Fields     map[string]any `json:"fields"`
	When       string         `json:"when"`
	By         string         `json:"by"`
	Restorable bool           `json:"restorable"`
}

var (
	dnsBinMu   sync.Mutex
	dnsBin     []dnsBinEntry // oldest first
	dnsBinFile string        // empty: kept in memory only (tests)
)

func initDNSBin(dir string) {
	dnsBinMu.Lock()
	defer dnsBinMu.Unlock()
	dnsBin = nil
	dnsBinFile = filepath.Join(dir, "dns-recycle.json")
	if b, err := os.ReadFile(dnsBinFile); err == nil {
		_ = json.Unmarshal(b, &dnsBin)
	}
}

// dnsBinSave writes the list; the caller holds dnsBinMu.
func dnsBinSave() error {
	if dnsBinFile == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dnsBinFile), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(dnsBin)
	tmp := dnsBinFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dnsBinFile)
}

func dnsBinAdd(e dnsBinEntry) {
	var id [8]byte
	rand.Read(id[:])
	e.ID = hex.EncodeToString(id[:])
	e.When = time.Now().UTC().Format("2006-01-02 15:04 UTC")
	dnsBinMu.Lock()
	defer dnsBinMu.Unlock()
	dnsBin = append(dnsBin, e)
	if len(dnsBin) > maxDNSBin {
		dnsBin = dnsBin[len(dnsBin)-maxDNSBin:]
	}
	_ = dnsBinSave()
}

// dnsBinList is newest first and never nil.
func dnsBinList() []dnsBinEntry {
	dnsBinMu.Lock()
	defer dnsBinMu.Unlock()
	out := make([]dnsBinEntry, 0, len(dnsBin))
	for i := len(dnsBin) - 1; i >= 0; i-- {
		out = append(out, dnsBin[i])
	}
	return out
}

func dnsBinGet(id string) (dnsBinEntry, bool) {
	dnsBinMu.Lock()
	defer dnsBinMu.Unlock()
	for _, e := range dnsBin {
		if e.ID == id {
			return e, true
		}
	}
	return dnsBinEntry{}, false
}

// dnsBinRemove drops one entry (or all of them when id is empty) and returns how many went.
func dnsBinRemove(id string) int {
	dnsBinMu.Lock()
	defer dnsBinMu.Unlock()
	if id == "" {
		n := len(dnsBin)
		dnsBin = nil
		_ = dnsBinSave()
		return n
	}
	for i, e := range dnsBin {
		if e.ID == id {
			dnsBin = append(dnsBin[:i], dnsBin[i+1:]...)
			_ = dnsBinSave()
			return 1
		}
	}
	return 0
}

// requireDNSBinAdmin: removing entries from the DNS bin is not an LDAP operation, so AD's ACLs cannot decide it; it is
// limited to Domain and Enterprise Admins, checked over the signed-in user's own connection.
func requireDNSBinAdmin(s *Session) error {
	var ok bool
	if err := s.With(func(c *Conn) (e error) { ok, e = isDomainAdmin(c, s); return e }); err != nil {
		return err
	}
	if !ok {
		return errors.New("only Domain Admins or Enterprise Admins can remove DNS records from the Recycle Bin")
	}
	return nil
}

// apiDNSRestore puts a deleted record back as the signed-in user, through the same path as the DNS page's New record, so
// AD's ACLs and the CNAME rule apply. The entry is dropped once the record is back.
func apiDNSRestore(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	e, ok := dnsBinGet(in.ID)
	if !ok {
		return nil, errors.New("not in the Recycle Bin")
	}
	if !e.Restorable {
		return nil, errors.New("this record type cannot be restored here")
	}
	if err := dnsApply(s, dnsReq{Zone: e.Zone, Name: e.Name, Type: e.Type, TTL: e.TTL, Fields: e.Fields}, false); err != nil {
		return nil, err
	}
	dnsBinRemove(e.ID)
	return map[string]string{"name": e.Name}, nil
}
