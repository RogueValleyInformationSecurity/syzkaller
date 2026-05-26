// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proxmox

import (
	"net/url"
	"strings"
	"testing"
)

func TestEncodeSSHKeys(t *testing.T) {
	// A key whose base64 body contains '+', '/' and '=' (all reserved) plus a
	// trailing newline and a comment with a space - the case that broke Proxmox.
	key := "ssh-ed25519 AAAAC3Nz+a/bQ== syzkaller\n"
	got := encodeSSHKeys(key)
	if strings.ContainsAny(got, "+ \n") {
		t.Errorf("encoded key still contains a literal +, space or newline: %q", got)
	}
	dec, err := url.QueryUnescape(got)
	if err != nil {
		t.Fatalf("encoded key is not valid url-encoding: %v", err)
	}
	if dec != strings.TrimSpace(key) {
		t.Errorf("round-trip mismatch: got %q want %q", dec, strings.TrimSpace(key))
	}
}

func baseConfig() *Config {
	return &Config{
		Count:          2,
		APIURL:         "https://pve:8006/api2/json",
		APITokenID:     "syzkaller@pve!fuzz",
		APITokenSecret: "secret",
		Nodes:          []NodeConfig{{Name: "pve1", Addr: "10.0.0.1"}},
		TemplateVMID:   9000,
		IPBase:         "10.0.0.10",
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{"valid", func(*Config) {}, false},
		{"zero count", func(c *Config) { c.Count = 0 }, true},
		{"too many", func(c *Config) { c.Count = 1001 }, true},
		{"no api url", func(c *Config) { c.APIURL = "" }, true},
		{"no token id", func(c *Config) { c.APITokenID = "" }, true},
		{"no token secret", func(c *Config) { c.APITokenSecret = "" }, true},
		{"no nodes", func(c *Config) { c.Nodes = nil }, true},
		{"node missing addr", func(c *Config) { c.Nodes = []NodeConfig{{Name: "pve1"}} }, true},
		{"node missing name", func(c *Config) { c.Nodes = []NodeConfig{{Addr: "10.0.0.1"}} }, true},
		{"no template", func(c *Config) { c.TemplateVMID = 0 }, true},
		{"full clone without storage", func(c *Config) { c.FullClone = true; c.Storage = "" }, true},
		{"full clone with storage", func(c *Config) { c.FullClone = true; c.Storage = "vm-rbd" }, false},
		{"no ip base", func(c *Config) { c.IPBase = "" }, true},
		{"bad ip base", func(c *Config) { c.IPBase = "not-an-ip" }, true},
		{"ipv6 ip base", func(c *Config) { c.IPBase = "fe80::1" }, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := baseConfig()
			test.mutate(cfg)
			err := cfg.validate()
			if (err != nil) != test.wantErr {
				t.Errorf("validate() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}

func TestAddIPv4(t *testing.T) {
	tests := []struct {
		base   string
		offset int
		want   string
	}{
		{"192.168.0.130", 0, "192.168.0.130"},
		{"192.168.0.130", 5, "192.168.0.135"},
		{"192.168.0.250", 10, "192.168.1.4"}, // carry across the third octet
		{"10.0.0.255", 1, "10.0.1.0"},
		{"10.0.0.1", 256, "10.0.1.1"},
	}
	for _, test := range tests {
		got, err := addIPv4(test.base, test.offset)
		if err != nil {
			t.Errorf("addIPv4(%q, %d) unexpected error: %v", test.base, test.offset, err)
			continue
		}
		if got != test.want {
			t.Errorf("addIPv4(%q, %d) = %q, want %q", test.base, test.offset, got, test.want)
		}
	}
	if _, err := addIPv4("bad", 1); err == nil {
		t.Errorf("addIPv4 with invalid base should fail")
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"linux-manager-0", "linux-manager-0"},
		{"Linux_Manager_3", "linux-manager-3"},
		{"my.host/name", "my-host-name"},
		{"--weird--", "weird"},
		{"!@#$", "syzkaller"},
	}
	for _, test := range tests {
		if got := sanitizeName(test.in); got != test.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

// TestRoundRobin documents the node-selection scheme used by Create.
func TestRoundRobin(t *testing.T) {
	nodes := []NodeConfig{{Name: "pve1"}, {Name: "pve2"}, {Name: "pve3"}}
	want := []string{"pve1", "pve2", "pve3", "pve1", "pve2"}
	for i, w := range want {
		if got := nodes[i%len(nodes)].Name; got != w {
			t.Errorf("index %d -> %q, want %q", i, got, w)
		}
	}
}
