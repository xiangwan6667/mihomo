package outbound

import (
	"strings"
	"testing"
)

func TestSnellVersion6(t *testing.T) {
	s, err := NewSnell(SnellOption{Name: "v6", Server: "127.0.0.1", Port: 443, Psk: "snell-v6-psk-123456", Version: 6, UDP: true})
	if err != nil {
		t.Fatalf("Snell v6 must initialize: %v", err)
	}
	if s.version != 6 {
		t.Fatalf("version = %d, want distinct v6 wire", s.version)
	}
	if !s.SupportUDP() {
		t.Fatal("Snell v6 must support UDP")
	}
}

func TestSnellV6Configuration(t *testing.T) {
	base := SnellOption{Name: "v6", Server: "127.0.0.1", Port: 443, Psk: "snell-v6-psk-123456", Version: 6, UDP: true}
	for _, mode := range []string{"", "default", "unshaped", "unsafe-raw"} {
		option := base
		option.V6Mode = mode
		option.ClientID = "client-7"
		if _, err := NewSnell(option); err != nil {
			t.Errorf("mode %q: %v", mode, err)
		}
	}
	for name, modify := range map[string]func(*SnellOption){
		"short-psk":            func(o *SnellOption) { o.Psk = "short" },
		"long-psk":             func(o *SnellOption) { o.Psk = strings.Repeat("p", 256) },
		"utf8-psk-bytes":       func(o *SnellOption) { o.Psk = strings.Repeat("字", 86) },
		"mode":                 func(o *SnellOption) { o.V6Mode = "unknown" },
		"long-client-id":       func(o *SnellOption) { o.ClientID = strings.Repeat("i", 256) },
		"utf8-client-id-bytes": func(o *SnellOption) { o.ClientID = strings.Repeat("字", 86) },
		"reuse":                func(o *SnellOption) { o.Reuse = true },
		"tls-wrapper":          func(o *SnellOption) { o.ObfsOpts = map[string]any{"mode": "tls"} },
		"http-wrapper":         func(o *SnellOption) { o.ObfsOpts = map[string]any{"mode": "http"} },
		"shadowtls-wrapper":    func(o *SnellOption) { o.ObfsOpts = map[string]any{"mode": "shadow-tls"} },
		"restls-wrapper":       func(o *SnellOption) { o.ObfsOpts = map[string]any{"mode": "restls"} },
		"jls-wrapper":          func(o *SnellOption) { o.ObfsOpts = map[string]any{"mode": "jls"} },
		"version":              func(o *SnellOption) { o.Version = 7 },
	} {
		t.Run(name, func(t *testing.T) {
			option := base
			modify(&option)
			if _, err := NewSnell(option); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	for _, count := range []int{12, 255} {
		option := base
		option.Psk = strings.Repeat("p", count)
		option.ClientID = strings.Repeat("i", 255)
		option.ObfsOpts = map[string]any{"mode": "none"}
		if _, err := NewSnell(option); err != nil {
			t.Errorf("boundary %d: %v", count, err)
		}
	}
}

func TestSnellLegacyVersionsAndWrappers(t *testing.T) {
	for _, version := range []int{0, 1, 2, 3, 4, 5} {
		for _, wrapper := range []string{"", "http", "tls"} {
			option := SnellOption{Name: "legacy", Server: "127.0.0.1", Port: 443, Psk: "old-short-psk", Version: version, ObfsOpts: map[string]any{"mode": wrapper}}
			s, err := NewSnell(option)
			if err != nil {
				t.Fatalf("v%d/%s: %v", version, wrapper, err)
			}
			want := version
			if want == 0 {
				want = 1
			}
			if want == 5 {
				want = 4
			}
			if s.version != want || s.obfsOption.Mode != wrapper || s.reuse != (version == 2) {
				t.Fatalf("v%d/%s behavior changed", version, wrapper)
			}
		}
	}
}
