package outbound

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/structure"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/miu"
)

// Raw segments reach into the TLS connections of metacubex/tls and metacubex/utls. If this fails after
// one of them has been upgraded, Miu still works, but without raw segments.
func TestMiuRawSegmentsUsable(t *testing.T) {
	if !miuRawUsable() {
		t.Fatal("the Miu self-test failed: raw segments would be disabled")
	}
}

func TestMiuOption(t *testing.T) {
	decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true, KeyReplacer: structure.DefaultKeyReplacer})
	parse := func(mapping map[string]any) (*Miu, error) {
		option := &MiuOption{}
		if err := decoder.Decode(mapping, option); err != nil {
			return nil, err
		}
		return NewMiu(*option)
	}
	base := func() map[string]any {
		return map[string]any{"name": "n", "type": "miu", "server": "example.com", "port": 443, "psk": "0123456789abcdef0123456789abcdef", "udp": true, "tls": true}
	}

	m, err := parse(base())
	if err != nil {
		t.Fatal(err)
	}
	if m.Type() != C.Miu || m.Type().String() != "Miu" || !m.SupportUDP() || m.Addr() != "example.com:443" || m.tlsConfig.Host != "example.com" {
		t.Fatalf("type %v, udp %v, addr %s, sni %s", m.Type(), m.SupportUDP(), m.Addr(), m.tlsConfig.Host)
	}
	_ = m.Close()

	for _, key := range []string{"sni", "servername"} {
		mapping := base()
		mapping[key] = "www.example.com"
		m, err := parse(mapping)
		if err != nil || m.tlsConfig.Host != "www.example.com" {
			t.Fatalf("%s: %v", key, err)
		}
		_ = m.Close()
	}
	bothNames := base()
	bothNames["sni"] = "preferred.example"
	bothNames["servername"] = "fallback.example"
	m, err = parse(bothNames)
	if err != nil || m.tlsConfig.Host != "preferred.example" {
		t.Fatalf("sni should take precedence over servername: %v", err)
	}
	_ = m.Close()

	reality := base()
	reality["reality-opts"] = map[string]any{"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "0123456789abcdef"}
	if _, err := parse(reality); err == nil {
		t.Fatal("reality-opts without client-fingerprint was accepted")
	}
	reality["client-fingerprint"] = "chrome"
	m, err = parse(reality)
	if err != nil || m.tlsConfig.Reality == nil {
		t.Fatalf("reality: %v", err)
	}
	_ = m.Close()
	reality["client-fingerprint"] = "none"
	if _, err := parse(reality); err == nil {
		t.Fatal("reality-opts with an unusable client-fingerprint was accepted")
	}

	short := base()
	short["psk"] = "short"
	if _, err := parse(short); err == nil {
		t.Fatal("a psk shorter than 16 characters was accepted")
	}
	missing := base()
	delete(missing, "psk")
	if _, err := parse(missing); err == nil {
		t.Fatal("a proxy without psk was accepted")
	}
}

func TestMiuRejectsTLS12BeforeAuthentication(t *testing.T) {
	cert, err := miu.SelfSignedCert("miu.test")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		server := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		})
		if err := server.Handshake(); err != nil {
			serverDone <- err
			return
		}
		var b [1]byte
		n, err := server.Read(b[:])
		if n != 0 || err == nil {
			serverDone <- errors.New("client sent authentication data over TLS 1.2")
			return
		}
		serverDone <- nil
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	m, err := NewMiu(MiuOption{Name: "test", Server: "127.0.0.1", Port: port, PSK: "0123456789abcdef", SNI: "miu.test", SkipCertVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := m.dialLane(ctx)
	if conn != nil {
		conn.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "must use TLS 1.3") {
		t.Fatalf("expected TLS 1.2 rejection, got %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
