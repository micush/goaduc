package main

// Purging the Recycle Bin on the other domain controllers.
//
// Deleted objects are removed from a DC's own database (ldbdel / samba-tool tombstones expunge) when the DC refuses the
// LDAP delete, and nothing replicates that. So that one click can clean every DC, goaduc asks the goaduc running on each
// other DC to do the same locally: it signs in there as the signed-in user (the peer checks that user's rights itself)
// and calls the same purge endpoint with local=true.
//
// The peers are taken from the directory's own list of DCs (never from the browser), reached on this goaduc's own
// port, and the signed-in user's password is only sent to a peer whose certificate is trusted: either it verifies
// against the system roots for that name, or its SHA-256 fingerprint matches one the person approved (pinned in
// peers.json in the data directory; a different certificate later is reported as "changed" and needs approving again).

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	peerMu    sync.Mutex
	peerPins  = map[string]string{} // lower-case DC host name -> approved SHA-256 fingerprint
	peerFile  string
	webPort   = "8443"                                                              // this goaduc's own port; peers are expected on the same one
	peerAddr  = func(host string) string { return net.JoinHostPort(host, webPort) } // tests point it at a fake peer
	peerTimes = struct{ probe, call time.Duration }{5 * time.Second, 3 * time.Minute}
)

func initPeers(dir string) {
	peerMu.Lock()
	defer peerMu.Unlock()
	peerPins = map[string]string{}
	peerFile = filepath.Join(dir, "peers.json")
	if b, err := os.ReadFile(peerFile); err == nil {
		_ = json.Unmarshal(b, &peerPins)
	}
}

func peerPinSet(host, fp string) {
	peerMu.Lock()
	defer peerMu.Unlock()
	peerPins[strings.ToLower(host)] = fp
	if peerFile == "" {
		return
	}
	if b, err := json.MarshalIndent(peerPins, "", "  "); err == nil {
		_ = writeAtomic(peerFile, b, 0o600)
	}
}

func peerPinGet(host string) string {
	peerMu.Lock()
	defer peerMu.Unlock()
	return peerPins[strings.ToLower(host)]
}

func certSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	parts := make([]string, len(sum))
	for i, v := range sum {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

type peerInfo struct {
	Host        string `json:"host"`
	State       string `json:"state"` // trusted | pinned | new | changed | unreachable
	Fingerprint string `json:"fingerprint,omitempty"`
	Error       string `json:"error,omitempty"`
}

// peerHosts lists the other domain controllers (NTDS Settings present), excluding the one this goaduc talks to.
func peerHosts(c *Conn, s *Session) ([]string, error) {
	self := ""
	if root, err := c.Read("", []string{"dnsHostName"}); err == nil {
		self = strings.ToLower(root.Get("dnsHostName"))
	}
	var out []string
	for _, d := range domainControllers(c, s) {
		h := strings.ToLower(strings.TrimSpace(d.DNS))
		if h != "" && h != self {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out, nil
}

// probePeer reads a peer's certificate without sending anything secret.
func probePeer(host string) peerInfo {
	pi := peerInfo{Host: host}
	d := net.Dialer{Timeout: peerTimes.probe}
	raw, err := d.Dial("tcp", peerAddr(host))
	if err != nil {
		pi.State, pi.Error = "unreachable", err.Error()
		return pi
	}
	raw.SetDeadline(time.Now().Add(peerTimes.probe))
	tc := tls.Client(raw, &tls.Config{ServerName: host, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	defer tc.Close()
	if err := tc.Handshake(); err != nil {
		pi.State, pi.Error = "unreachable", err.Error()
		return pi
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		pi.State, pi.Error = "unreachable", "no certificate presented"
		return pi
	}
	pi.Fingerprint = certSHA256(certs[0].Raw)
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err == nil {
		pi.State = "trusted"
		return pi
	}
	switch pin := peerPinGet(host); {
	case pin == "":
		pi.State = "new"
	case pin == pi.Fingerprint:
		pi.State = "pinned"
	default:
		pi.State = "changed"
	}
	return pi
}

// peerClient trusts exactly: a certificate that verifies for the host, or the one with the approved fingerprint.
func peerClient(host, approvedFP string) *http.Client {
	jar, _ := cookiejar.New(nil)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: peerTimes.probe}).DialContext(ctx, network, peerAddr(host))
		},
		TLSClientConfig: &tls.Config{
			ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, // verified by hand below
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				if len(raw) == 0 {
					return errors.New("no certificate presented")
				}
				leaf, err := x509.ParseCertificate(raw[0])
				if err != nil {
					return err
				}
				inter := x509.NewCertPool()
				for _, r := range raw[1:] {
					if c, err := x509.ParseCertificate(r); err == nil {
						inter.AddCert(c)
					}
				}
				if _, err := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: inter}); err == nil {
					return nil
				}
				if approvedFP != "" && strings.EqualFold(approvedFP, certSHA256(raw[0])) {
					return nil
				}
				return errors.New("the certificate is not trusted and does not match the approved fingerprint")
			},
		},
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr, Jar: jar, Timeout: peerTimes.call,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func peerPost(cl *http.Client, host, path string, body any) (map[string]any, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", "https://"+host+path, strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "aduc")
	resp, err := cl.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	if resp.StatusCode != 200 {
		msg, _ := out["error"].(string)
		if msg == "" {
			msg = resp.Status
		}
		return out, errors.New(msg)
	}
	return out, nil
}

type peerResult struct {
	Host    string `json:"host"`
	OK      bool   `json:"ok"`
	Deleted int    `json:"deleted,omitempty"`
	Error   string `json:"error,omitempty"`
}

// purgeOnPeer signs in on the peer's goaduc as the signed-in user and repeats the purge there, locally.
func purgeOnPeer(s *Session, host, approvedFP string, purge map[string]any) peerResult {
	res := peerResult{Host: host}
	cl := peerClient(host, approvedFP)
	if _, err := peerPost(cl, host, "/api/login", map[string]string{"username": s.user, "password": s.pass}); err != nil {
		res.Error = "sign-in: " + err.Error()
		return res
	}
	defer peerPost(cl, host, "/api/logout", map[string]any{})
	purge["local"] = true
	out, err := peerPost(cl, host, "/api/deleted/purge", purge)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.OK = true
	if n, ok := out["deleted"].(float64); ok {
		res.Deleted = int(n)
	}
	if approvedFP != "" {
		peerPinSet(host, approvedFP) // approved and it worked: remember it
	}
	return res
}
