package outbound

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/miu"
)

func TestMiuTCPAndUDP(t *testing.T) {
	const psk = "miu-integration-test-password"
	cert, err := miu.SelfSignedCert("miu.test")
	if err != nil {
		t.Fatal(err)
	}
	accesses := make(chan miu.Access, 16)
	server, err := miu.NewServer(miu.ServerConfig{
		Users:    []miu.User{{Name: "test", PSK: psk}},
		OnAccess: func(a miu.Access) { accesses <- a },
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			client, target := net.Pipe()
			go func() {
				defer target.Close()
				_, _ = io.Copy(target, target)
			}()
			return client, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
				_ = server.Serve(ctx, tlsConn)
			}()
		}
	}()

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udp.WriteToUDP(buf[:n], addr)
		}
	}()

	for _, fingerprint := range []string{"", "chrome"} {
		t.Run("fingerprint="+fingerprint, func(t *testing.T) {
			proxy, err := NewMiu(MiuOption{
				Name: "test", Server: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port,
				PSK: psk, UDP: true, SNI: "miu.test", SkipCertVerify: true, ClientFingerprint: fingerprint,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = proxy.Close() })
			conn, err := proxy.DialContext(ctx, &C.Metadata{Host: "example.invalid", DstPort: 443})
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			payload := []byte("hello through Miu")
			if _, err := conn.Write(payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("TCP echo: %q, %v", got, err)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case access := <-accesses:
				if access.Network != "tcp" || access.Target != "example.invalid:443" {
					t.Fatalf("TCP target was not preserved: %+v", access)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("server did not receive TCP target")
			}

			addr := udp.LocalAddr().(*net.UDPAddr)
			metadata := &C.Metadata{DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(addr.Port)}
			pc, err := proxy.ListenPacketContext(ctx, metadata)
			if err != nil {
				t.Fatal(err)
			}
			defer pc.Close()
			_ = pc.SetDeadline(time.Now().Add(10 * time.Second))
			for _, size := range []int{5, 600, 4000} {
				data := bytes.Repeat([]byte{byte(size)}, size)
				if _, err := pc.WriteTo(data, addr); err != nil {
					t.Fatal(err)
				}
				buf := make([]byte, size+1)
				n, from, err := pc.ReadFrom(buf)
				if err != nil || !bytes.Equal(buf[:n], data) || from.String() != addr.String() {
					t.Fatalf("UDP echo: size=%d from=%v err=%v", n, from, err)
				}
			}
			select {
			case access := <-accesses:
				if access.Network != "udp" || access.Target != addr.String() {
					t.Fatalf("unexpected UDP target: %+v", access)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("server did not receive UDP target")
			}
			if err := proxy.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := proxy.DialContext(ctx, &C.Metadata{Host: "example.invalid", DstPort: 443}); !errors.Is(err, miu.ErrClientClosed) {
				t.Fatalf("dial after closing the proxy: %v", err)
			}
		})
	}
	t.Run("invalid-psk", func(t *testing.T) {
		proxy, err := NewMiu(MiuOption{
			Name: "invalid-psk", Server: "127.0.0.1", Port: listener.Addr().(*net.TCPAddr).Port,
			PSK: "incorrect-integration-test-password", SNI: "miu.test", SkipCertVerify: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer proxy.Close()
		conn, err := proxy.DialContext(ctx, &C.Metadata{Host: "example.invalid", DstPort: 443})
		if err != nil {
			return // The server rejected the connection before a stream was returned.
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write([]byte("must not reach the target")); err != nil {
			return
		}
		var buf [1]byte
		if n, err := conn.Read(buf[:]); n != 0 || err == nil {
			t.Fatalf("invalid PSK reached the target: n=%d err=%v", n, err)
		} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("invalid PSK was not rejected promptly: %v", err)
		}
	})
}
