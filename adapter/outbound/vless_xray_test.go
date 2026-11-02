package outbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/miu"
)

func TestVlessRejectsUnsupportedNetworks(t *testing.T) {
	for _, network := range []string{"unknown", "kcp", "mkcp", "hysteria", "masque", "xdrive", "quic", "h3"} {
		t.Run(network, func(t *testing.T) {
			v, err := NewVless(VlessOption{Network: network})
			if err == nil {
				_ = v.Close()
				t.Fatalf("unsupported transport %q silently fell back to TCP", network)
			}
		})
	}
}

func TestVlessTransportAliases(t *testing.T) {
	for _, tc := range []struct{ network, normalized string }{
		{"", "tcp"}, {"tcp", "tcp"}, {"raw", "tcp"}, {"RAW", "tcp"},
		{"ws", "ws"}, {"websocket", "ws"}, {"httpupgrade", "ws"},
		{"http", "http"}, {"h2", "h2"}, {"grpc", "grpc"},
		{"xhttp", "xhttp"}, {"splithttp", "xhttp"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			v, err := NewVless(VlessOption{Network: tc.network, Server: "127.0.0.1", Port: 443})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if v.option.Network != tc.normalized {
				t.Fatalf("network = %q, want %q", v.option.Network, tc.normalized)
			}
			if tc.normalized == "xhttp" && v.xhttpClient == nil {
				t.Fatal("XHTTP transport was not initialized")
			}
			if tc.network == "httpupgrade" && !v.option.WSOpts.V2rayHttpUpgrade {
				t.Fatal("HTTPUpgrade mapped to framed WebSocket")
			}
		})
	}
}

func TestVlessRejectsRealityOnIncompatibleTransports(t *testing.T) {
	for _, network := range []string{"ws", "websocket", "http", "h2", "httpupgrade"} {
		t.Run(network, func(t *testing.T) {
			v, err := NewVless(VlessOption{Network: network, TLS: true, RealityOpts: RealityOptions{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}})
			if err == nil {
				_ = v.Close()
				t.Fatalf("REALITY with %s was accepted", network)
			}
		})
	}
}

func TestVlessPreservesSupportedRealityTransports(t *testing.T) {
	for _, network := range []string{"", "tcp", "raw", "xhttp", "splithttp", "grpc"} {
		t.Run(network, func(t *testing.T) {
			v, err := NewVless(VlessOption{Server: "127.0.0.1", Port: 443, Network: network, TLS: true, RealityOpts: RealityOptions{PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}})
			if err != nil {
				t.Fatal(err)
			}
			_ = v.Close()
		})
	}
}

func TestVlessRejectsVisionPacketAddr(t *testing.T) {
	for _, flow := range []string{"xtls-rprx-vision", "xtls-rprx-vision-udp443"} {
		for _, encoding := range []string{"packet", "packetaddr", "legacy-boolean"} {
			t.Run(flow+"/"+encoding, func(t *testing.T) {
				option := VlessOption{Flow: flow, PacketEncoding: encoding}
				if encoding == "legacy-boolean" {
					option.PacketEncoding = ""
					option.PacketAddr = true
				}
				v, err := NewVless(option)
				if err == nil {
					_ = v.Close()
					t.Fatal("Vision with non-XUDP packet addressing was accepted")
				}
			})
		}
	}
}

func TestVlessPreservesPacketAddrWithoutVision(t *testing.T) {
	for _, encoding := range []string{"packet", "packetaddr", "legacy-boolean"} {
		t.Run(encoding, func(t *testing.T) {
			option := VlessOption{PacketEncoding: encoding}
			if encoding == "legacy-boolean" {
				option.PacketEncoding = ""
				option.PacketAddr = true
			}
			v, err := NewVless(option)
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			if !v.option.PacketAddr || v.option.XUDP {
				t.Fatal("legacy packet addressing was replaced with XUDP")
			}
		})
	}
}

func TestVlessHTTPUpgradeUsesUnframedStream(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		req, err := http.ReadRequest(reader)
		if err != nil {
			result <- err
			return
		}
		if req.URL.Path != "/upgrade" || req.Host != "upgrade.test" || !strings.EqualFold(req.Header.Get("Upgrade"), "websocket") || !strings.EqualFold(req.Header.Get("Connection"), "upgrade") {
			result <- fmt.Errorf("unexpected upgrade request: %s %s %v", req.Host, req.URL.Path, req.Header)
			return
		}
		if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
			result <- err
			return
		}
		want := append([]byte{0, 0, 0, 0, 0, 0, 0, 64, 0, 128, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 187, 1, 127, 0, 0, 1}, []byte("payload")...)
		got := make([]byte, len(want))
		if _, err := io.ReadFull(reader, got); err != nil {
			result <- err
			return
		}
		if !bytes.Equal(got, want) {
			result <- fmt.Errorf("upgraded VLESS stream: got %x, want %x", got, want)
			return
		}
		result <- nil
	}()
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	v, err := NewVless(VlessOption{Server: host, Port: port, UUID: "00000000-0000-4000-8000-000000000001", Network: "httpupgrade", WSOpts: WSOptions{Path: "/upgrade", Headers: map[string]string{"Host": "upgrade.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := v.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestVlessRejectsUnsupportedXrayFlows(t *testing.T) {
	for _, flow := range []string{
		"vision", "xtls-rprx-direct", "xtls-rprx-vision-extra",
		"xtls-rprx-vision-udp443-extra", "xtls-rprx-vision ",
	} {
		t.Run(flow, func(t *testing.T) {
			v, err := NewVless(VlessOption{Flow: flow})
			if err == nil {
				_ = v.Close()
				t.Fatalf("unsupported flow %q was accepted", flow)
			}
		})
	}
}

func TestVlessVisionRejectsUDP443BeforeTransport(t *testing.T) {
	v, err := NewVless(VlessOption{Server: "127.0.0.1", Port: 1, Flow: "xtls-rprx-vision"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	metadata := &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: 443}
	if _, err := v.ListenPacketContext(context.Background(), metadata); err == nil || !strings.Contains(err.Error(), "UDP/443") {
		t.Fatalf("packet request should reject UDP/443 before dialing: %v", err)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if _, err := v.StreamConnContext(context.Background(), client, metadata); err == nil || !strings.Contains(err.Error(), "UDP/443") {
		t.Fatalf("stream request should reject UDP/443: %v", err)
	}
}

func TestVlessXrayFlowWireAndUDPPolicy(t *testing.T) {
	for _, tc := range []struct {
		flow     string
		port     uint16
		block443 bool
		wireFlow string
	}{
		{flow: "", port: 443},
		{flow: "xtls-rprx-vision", port: 53, block443: true, wireFlow: "xtls-rprx-vision"},
		{flow: "xtls-rprx-vision-udp443", port: 443, wireFlow: "xtls-rprx-vision"},
	} {
		t.Run(tc.flow, func(t *testing.T) {
			cert, err := miu.SelfSignedCert("localhost")
			if err != nil {
				t.Fatal(err)
			}
			listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			result := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					result <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				header := make([]byte, 18)
				if _, err := io.ReadFull(conn, header); err != nil {
					result <- err
					return
				}
				addons := make([]byte, int(header[17]))
				if _, err := io.ReadFull(conn, addons); err != nil {
					result <- err
					return
				}
				want := ""
				if tc.wireFlow != "" {
					want = "\x0a\x10xtls-rprx-vision"
				}
				if string(addons) != want {
					result <- fmt.Errorf("VLESS wire addons: got %q, want %q", addons, want)
					return
				}
				result <- nil
			}()
			host, portText, _ := net.SplitHostPort(listener.Addr().String())
			port, _ := strconv.Atoi(portText)
			v, err := NewVless(VlessOption{Server: host, Port: port, UUID: "00000000-0000-4000-8000-000000000001", TLS: true, SkipCertVerify: true, Flow: tc.flow, UDP: true})
			if err != nil {
				t.Fatal(err)
			}
			defer v.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			pc, err := v.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: tc.port})
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			_ = pc.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if tc.block443 {
				if _, err := pc.WriteTo([]byte("blocked"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}); err == nil || !strings.Contains(err.Error(), "UDP/443") {
					t.Fatalf("reused XUDP connection should reject UDP/443: %v", err)
				}
			}
			if _, err := pc.WriteTo([]byte("payload"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(tc.port)}); err != nil {
				t.Fatal(err)
			}
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		})
	}
}
