package outbound

import (
	"strings"
	"testing"
)

func TestVmessRejectsUnsupportedNetworks(t *testing.T) {
	for _, network := range []string{"unknown", "xhttp", "splithttp", "h3", "quic", "hysteria", "masque", "xdrive"} {
		t.Run(network, func(t *testing.T) {
			v, err := NewVmess(VmessOption{UUID: "00000000-0000-4000-8000-000000000001", Cipher: "auto", Network: network})
			if err == nil {
				_ = v.Close()
				t.Fatalf("VMess transport %q silently fell back to TCP", network)
			}
			if !strings.Contains(err.Error(), "network") {
				t.Fatalf("wrong rejection: %v", err)
			}
		})
	}
}

func TestTrojanRejectsUnsupportedNetworks(t *testing.T) {
	for _, network := range []string{"unknown", "xhttp", "splithttp", "http", "h2", "h3", "quic", "kcp", "mkcp", "mekya", "hysteria", "masque", "xdrive"} {
		t.Run(network, func(t *testing.T) {
			v, err := NewTrojan(TrojanOption{Network: network})
			if err == nil {
				_ = v.Close()
				t.Fatalf("Trojan transport %q silently fell back to TCP", network)
			}
			if !strings.Contains(err.Error(), "network") {
				t.Fatalf("wrong rejection: %v", err)
			}
		})
	}
}

func TestVmessPreservesSupportedTransportsAndAliases(t *testing.T) {
	for _, tc := range []struct{ network, normalized string }{
		{"", "tcp"}, {"tcp", "tcp"}, {"raw", "tcp"}, {"RAW", "tcp"},
		{"ws", "ws"}, {"websocket", "ws"}, {"httpupgrade", "ws"},
		{"http", "http"}, {"h2", "h2"}, {"grpc", "grpc"},
		{"mkcp", "mkcp"}, {"kcp", "kcp"}, {"mekya", "mekya"}, {"MKCP", "mkcp"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			v, err := NewVmess(VmessOption{UUID: "00000000-0000-4000-8000-000000000001", Cipher: "auto", Network: tc.network, Server: "127.0.0.1", Port: 443, WSOpts: WSOptions{Path: "/upgrade", Headers: map[string]string{"Host": "upgrade.test"}}})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if v.option.Network != tc.normalized {
				t.Fatalf("network = %q, want %q", v.option.Network, tc.normalized)
			}
			if tc.network == "httpupgrade" && (!v.option.WSOpts.V2rayHttpUpgrade || v.option.WSOpts.Path != "/upgrade" || v.option.WSOpts.Headers["Host"] != "upgrade.test") {
				t.Fatal("HTTPUpgrade alias lost the unframed upgrade flag or WS options")
			}
			if tc.normalized == "grpc" && v.gunClient == nil {
				t.Fatal("gRPC client was not initialized")
			}
			if tc.normalized == "mekya" && v.mekyaClient == nil {
				t.Fatal("Mekya client was not initialized")
			}
		})
	}
}

func TestTrojanPreservesSupportedTransportsAndAliases(t *testing.T) {
	for _, tc := range []struct{ network, normalized string }{
		{"", "tcp"}, {"tcp", "tcp"}, {"raw", "tcp"}, {"RAW", "tcp"},
		{"ws", "ws"}, {"websocket", "ws"}, {"httpupgrade", "ws"}, {"grpc", "grpc"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			v, err := NewTrojan(TrojanOption{Network: tc.network, Server: "127.0.0.1", Port: 443, WSOpts: WSOptions{Path: "/upgrade", Headers: map[string]string{"Host": "upgrade.test"}}})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if v.option.Network != tc.normalized {
				t.Fatalf("network = %q, want %q", v.option.Network, tc.normalized)
			}
			if tc.network == "httpupgrade" && (!v.option.WSOpts.V2rayHttpUpgrade || v.option.WSOpts.Path != "/upgrade" || v.option.WSOpts.Headers["Host"] != "upgrade.test") {
				t.Fatal("HTTPUpgrade alias lost the unframed upgrade flag or WS options")
			}
			if tc.normalized == "grpc" && v.gunClient == nil {
				t.Fatal("gRPC client was not initialized")
			}
		})
	}
}

func TestVmessAndTrojanRealityTransportValidation(t *testing.T) {
	reality := RealityOptions{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
	for _, network := range []string{"ws", "websocket", "httpupgrade", "http", "h2", "mkcp", "kcp", "mekya"} {
		t.Run("vmess/"+network, func(t *testing.T) {
			v, err := NewVmess(VmessOption{UUID: "00000000-0000-4000-8000-000000000001", Cipher: "auto", Network: network, TLS: true, RealityOpts: reality})
			if err == nil {
				_ = v.Close()
				t.Fatalf("REALITY with %s was accepted", network)
			}
			if !strings.Contains(err.Error(), "REALITY") {
				t.Fatalf("wrong rejection: %v", err)
			}
		})
	}
	for _, network := range []string{"ws", "websocket", "httpupgrade"} {
		t.Run("trojan/"+network, func(t *testing.T) {
			v, err := NewTrojan(TrojanOption{Network: network, RealityOpts: reality})
			if err == nil {
				_ = v.Close()
				t.Fatalf("REALITY with %s was accepted", network)
			}
			if !strings.Contains(err.Error(), "REALITY") {
				t.Fatalf("wrong rejection: %v", err)
			}
		})
	}
	for _, network := range []string{"", "tcp", "raw", "grpc"} {
		t.Run("supported/"+network, func(t *testing.T) {
			v, err := NewVmess(VmessOption{UUID: "00000000-0000-4000-8000-000000000001", Cipher: "auto", Network: network, TLS: true, RealityOpts: reality})
			if err != nil {
				t.Fatal(err)
			}
			_ = v.Close()
			tr, err := NewTrojan(TrojanOption{Network: network, RealityOpts: reality})
			if err != nil {
				t.Fatal(err)
			}
			_ = tr.Close()
		})
	}
}
