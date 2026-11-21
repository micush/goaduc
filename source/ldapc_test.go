package main

import (
	"bufio"
	"bytes"
	"net"
	"testing"
)

func TestFilter(t *testing.T) {
	f, err := ParseFilter("(cn=a)")
	if err != nil || !bytes.Equal(f, []byte{0xa3, 7, 4, 2, 'c', 'n', 4, 1, 'a'}) {
		t.Fatalf("%x %v", f, err)
	}
	for _, s := range []string{"(&(objectClass=user)(!(cn=x*y*)))", "(|(a=*)(b>=3)(c<=\\2a))", "(userAccountControl:1.2.840.113556.1.4.803:=2)", "(sn=*smith)"} {
		if _, err := ParseFilter(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	for _, s := range []string{"cn=a", "(cn=a", "(cn=\\z)", "(=x)", "(cn=a)x"} {
		if _, err := ParseFilter(s); err == nil {
			t.Errorf("%s: expected error", s)
		}
	}
}

func TestInt(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 255, 256, -1, -128, -129, 70000, 1 << 30} {
		if g := parseInt(intBytes(n)); g != n {
			t.Errorf("%d -> %d", n, g)
		}
	}
}

func TestLoopback(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		r := bufio.NewReader(c)
		for {
			m, err := readTLV(r)
			if err != nil {
				return
			}
			k, _ := parseAll(m.val)
			id := k[0].val
			wrap := func(op []byte) []byte { return enc(0x30, cat(enc(0x02, id), op)) }
			res := cat(bEnum(0), bOctet(""), bOctet(""))
			switch k[1].tag {
			case 0x60:
				c.Write(wrap(enc(0x61, res)))
			case 0x63:
				attrs := enc(0x30, cat(enc(0x30, cat(bOctet("cn"), enc(0x31, bOctet("bob")))),
					enc(0x30, cat(bOctet("objectClass"), enc(0x31, cat(bOctet("top"), bOctet("user")))))))
				c.Write(wrap(enc(0x64, cat(bOctet("CN=bob,DC=x"), attrs))))
				done := enc(0x30, cat(enc(0x02, id), enc(0x65, res), enc(0xa0, control(oidPaged, false, enc(0x30, cat(bInt(0), bOctetB(nil)))))))
				c.Write(done)
			case 0x66, 0x68, 0x6c:
				c.Write(wrap(enc(k[1].tag+1, cat(bEnum(50), bOctet(""), bOctet("denied")))))
			case 0x4a:
				c.Write(wrap(enc(0x6b, res)))
			}
		}
	}()
	c, err := Dial(&Config{URL: "ldap://" + ln.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Bind("u", ""); err == nil {
		t.Fatal("empty password must be rejected")
	}
	if err := c.Bind("u", "p"); err != nil {
		t.Fatal(err)
	}
	es, trunc, err := c.Search("DC=x", ScopeSub, "(cn=bob)", []string{"*"}, 10)
	if err != nil || trunc || len(es) != 1 || es[0].Get("cn") != "bob" || kindOf(es[0].Strs("objectClass")) != "user" {
		t.Fatalf("%+v %v %v", es, trunc, err)
	}
	err = c.Modify("CN=bob,DC=x", []Mod{{Op: 2, Attr: "description", Vals: sv("x")}})
	if le, ok := err.(*LDAPError); !ok || le.Code != 50 {
		t.Fatalf("%v", err)
	}
	if err := c.Delete("CN=bob,DC=x", true); err != nil {
		t.Fatal(err)
	}
}

func TestDN(t *testing.T) {
	if g := escapeRDN(" a,b+c "); g != "\\ a\\,b\\+c\\ " {
		t.Error(g)
	}
	if p := parentDN("CN=a\\,b,OU=x,DC=y"); p != "OU=x,DC=y" {
		t.Error(p)
	}
	if realmFromBase("DC=samdom,DC=example,DC=com") != "samdom.example.com" {
		t.Error("realm")
	}
}
