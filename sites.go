package main

// Active Directory Sites and Services support: creation of sites, subnets,
// site links and replication connections in the Configuration partition.
// Everything else (browse, edit attributes, rename, move, delete) reuses the
// generic object endpoints.

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func apiSitesCreate(w http.ResponseWriter, r *http.Request, s *Session) (any, error) {
	var in struct {
		Kind        string   `json:"kind"` // site | subnet | sitelink | connection
		Parent      string   `json:"parent"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Location    string   `json:"location"`
		Site        string   `json:"site"`     // subnet: DN of site
		SiteLink    string   `json:"siteLink"` // site: optional DN of site link to join
		Cost        int      `json:"cost"`     // sitelink
		Interval    int      `json:"interval"` // sitelink, minutes
		Sites       []string `json:"sites"`    // sitelink: DNs
		ChangeNotif bool     `json:"changeNotify"`
		From        string   `json:"from"` // connection: DN of source NTDS Settings
	}
	if err := decode(r, &in); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, errors.New("name is required")
	}
	sites := "CN=Sites," + s.config
	inSites := func(dn string) bool { return within(dn, sites) && !strings.EqualFold(dn, sites) }
	checkSite := func(c *Conn, dn string) error {
		if !inSites(dn) {
			return fmt.Errorf("%q is not a site", dn)
		}
		e, err := c.Read(dn, []string{"objectClass"})
		if err != nil {
			return err
		}
		if kindOf(e.Strs("objectClass")) != "site" {
			return fmt.Errorf("%q is not a site", dn)
		}
		return nil
	}
	oc := func(cls ...string) Mod { return Mod{Attr: "objectClass", Vals: svs(cls)} }
	opt := func(a, v string) []Mod {
		if v == "" {
			return nil
		}
		return []Mod{{Attr: a, Vals: sv(v)}}
	}

	switch in.Kind {
	case "site":
		if strings.ContainsAny(in.Name, "/\\") {
			return nil, errors.New("invalid site name")
		}
		dn := "CN=" + escapeRDN(in.Name) + "," + sites
		err := s.With(func(c *Conn) error {
			if in.SiteLink != "" {
				if !within(in.SiteLink, "CN=Inter-Site Transports,"+sites) {
					return errors.New("invalid site link")
				}
			}
			attrs := append([]Mod{oc("top", "site")}, opt("description", in.Description)...)
			attrs = append(attrs, opt("location", in.Location)...)
			if err := c.Add(dn, attrs); err != nil {
				return err
			}
			rollback := func(err error) error { c.Delete(dn, true); return err }
			// the standard child objects every site has
			if err := c.Add("CN=Servers,"+dn, []Mod{oc("top", "serversContainer")}); err != nil {
				return rollback(err)
			}
			if err := c.Add("CN=NTDS Site Settings,"+dn, []Mod{oc("top", "applicationSiteSettings", "nTDSSiteSettings"), {Attr: "options", Vals: sv("0")}}); err != nil {
				return rollback(err)
			}
			if in.SiteLink != "" {
				if err := c.Modify(in.SiteLink, []Mod{{Op: 0, Attr: "siteList", Vals: sv(dn)}}); err != nil {
					return rollback(fmt.Errorf("could not add the site to the site link: %w", err))
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		return map[string]string{"dn": dn}, nil

	case "subnet":
		ip, n, err := net.ParseCIDR(in.Name)
		if err != nil {
			return nil, errors.New("subnet must be in CIDR form, e.g. 10.1.0.0/24 or fd00::/64")
		}
		if !ip.Equal(n.IP) {
			return nil, fmt.Errorf("%s has host bits set; did you mean %s?", in.Name, n.String())
		}
		name := n.String()
		dn := "CN=" + name + ",CN=Subnets," + sites
		err = s.With(func(c *Conn) error {
			attrs := []Mod{oc("top", "subnet")}
			if in.Site != "" {
				if err := checkSite(c, in.Site); err != nil {
					return err
				}
				attrs = append(attrs, opt("siteObject", in.Site)...)
			}
			attrs = append(attrs, opt("location", in.Location)...)
			attrs = append(attrs, opt("description", in.Description)...)
			return c.Add(dn, attrs)
		})
		if err != nil {
			return nil, err
		}
		return map[string]string{"dn": dn}, nil

	case "sitelink":
		if in.Cost == 0 {
			in.Cost = 100
		}
		if in.Interval == 0 {
			in.Interval = 180
		}
		if in.Cost < 1 || in.Cost > 99999 {
			return nil, errors.New("cost must be between 1 and 99999")
		}
		if in.Interval < 15 || in.Interval > 10080 {
			return nil, errors.New("replication interval must be between 15 and 10080 minutes")
		}
		if len(in.Sites) < 2 {
			return nil, errors.New("a site link needs at least two sites")
		}
		dn := "CN=" + escapeRDN(in.Name) + ",CN=IP,CN=Inter-Site Transports," + sites
		err := s.With(func(c *Conn) error {
			for _, sd := range in.Sites {
				if err := checkSite(c, sd); err != nil {
					return err
				}
			}
			attrs := []Mod{oc("top", "siteLink"),
				{Attr: "siteList", Vals: svs(in.Sites)},
				{Attr: "cost", Vals: sv(strconv.Itoa(in.Cost))},
				{Attr: "replInterval", Vals: sv(strconv.Itoa(in.Interval))}}
			if in.ChangeNotif {
				attrs = append(attrs, Mod{Attr: "options", Vals: sv("1")})
			}
			attrs = append(attrs, opt("description", in.Description)...)
			return c.Add(dn, attrs)
		})
		if err != nil {
			return nil, err
		}
		return map[string]string{"dn": dn}, nil

	case "connection":
		if !within(in.Parent, sites) || in.From == "" || !within(in.From, sites) {
			return nil, errors.New("a connection needs a destination NTDS Settings object and a source server")
		}
		if strings.EqualFold(in.Parent, in.From) {
			return nil, errors.New("a server cannot replicate from itself")
		}
		dn := "CN=" + escapeRDN(in.Name) + "," + in.Parent
		err := s.With(func(c *Conn) error {
			for _, d := range []string{in.Parent, in.From} {
				e, err := c.Read(d, []string{"objectClass"})
				if err != nil {
					return err
				}
				if kindOf(e.Strs("objectClass")) != "ntds" {
					return fmt.Errorf("%q is not an NTDS Settings object", d)
				}
			}
			return c.Add(dn, []Mod{oc("top", "nTDSConnection"),
				{Attr: "enabledConnection", Vals: sv("TRUE")},
				{Attr: "fromServer", Vals: sv(in.From)},
				{Attr: "options", Vals: sv("0")}, // 0 = manually created (not KCC-generated)
				{Attr: "transportType", Vals: sv("CN=IP,CN=Inter-Site Transports," + sites)}})
		})
		if err != nil {
			return nil, err
		}
		return map[string]string{"dn": dn}, nil
	}
	return nil, errors.New("unknown object kind")
}
