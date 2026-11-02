package snell

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

var v6TestPSK = []byte("snell-v6-test-psk-123456")

func v6TestConn(t *testing.T, raw net.Conn, mode string, server bool) *Snell {
	t.Helper()
	c, err := StreamConnV6(raw, v6TestPSK, mode)
	if err != nil {
		t.Fatal(err)
	}
	c.reply = server
	return c
}

type v6ShortConn struct {
	bufferConn
	limit int
}

func (c *v6ShortConn) Write(p []byte) (int, error) {
	if len(p) > c.limit {
		p = p[:c.limit]
	}
	return c.Buffer.Write(p)
}

func TestSnellV6RecordStream(t *testing.T) {
	for _, mode := range []string{"default", "unshaped", "unsafe-raw"} {
		t.Run(mode, func(t *testing.T) {
			raw := &v6ShortConn{limit: 11}
			writer := v6TestConn(t, raw, mode, true)
			payload := bytes.Repeat([]byte("record-payload"), 8000)
			if n, err := writer.Write(payload); err != nil || n != len(payload) {
				t.Fatalf("write = %d, %v", n, err)
			}
			if _, err := writer.Write(nil); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte("after EOF")); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("write after EOF = %v", err)
			}
			reader := v6TestConn(t, &bufferConn{Buffer: *bytes.NewBuffer(raw.Bytes())}, mode, true)
			if n, err := reader.Read(nil); n != 0 || err != nil {
				t.Fatalf("empty read = %d, %v", n, err)
			}
			got, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("read = %d bytes, %v", len(got), err)
			}
			if _, err := reader.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("EOF not persistent: %v", err)
			}
		})
	}
}

func TestSnellV6TruncatedRecord(t *testing.T) {
	for _, mode := range []string{"default", "unshaped", "unsafe-raw"} {
		t.Run(mode, func(t *testing.T) {
			raw := &bufferConn{}
			writer := v6TestConn(t, raw, mode, true)
			if _, err := writer.Write([]byte("must not truncate")); err != nil {
				t.Fatal(err)
			}
			wire := append([]byte(nil), raw.Bytes()...)
			complete := v6TestConn(t, &bufferConn{Buffer: *bytes.NewBuffer(wire)}, mode, true)
			if got, err := io.ReadAll(complete); err != nil || string(got) != "must not truncate" {
				t.Fatalf("complete record before TCP EOF = %q, %v", got, err)
			}
			for cut := 1; cut < len(wire); cut++ {
				reader := v6TestConn(t, &bufferConn{Buffer: *bytes.NewBuffer(wire[:cut])}, mode, true)
				if _, err := io.ReadAll(reader); err == nil || errors.Is(err, io.EOF) {
					t.Fatalf("cut %d/%d accepted truncated record: %v", cut, len(wire), err)
				}
			}
		})
	}
}

func TestSnellV6MalformedHeader(t *testing.T) {
	for _, header := range [][]byte{
		{5, 0, 0, 0, 0, 0, 1},
		{4, 1, 0, 0, 0, 0, 1},
		{4, 0, 1, 0, 0, 0, 1},
		{4, 0, 0, 0, 1, 0, 1},
	} {
		reader := v6TestConn(t, &bufferConn{Buffer: *bytes.NewBuffer(append(header, 'x'))}, "unsafe-raw", true)
		if _, err := reader.Read(make([]byte, 1)); err == nil {
			t.Fatalf("accepted invalid header: %x", header)
		}
	}
}

func TestSnellV6AuthenticatedRecords(t *testing.T) {
	for _, mode := range []string{"default", "unshaped"} {
		t.Run(mode, func(t *testing.T) {
			raw := &bufferConn{}
			writer := v6TestConn(t, raw, mode, true)
			if _, err := writer.Write([]byte("authenticated payload")); err != nil {
				t.Fatal(err)
			}
			wire := append([]byte(nil), raw.Bytes()...)
			wire[len(wire)-1] ^= 1
			reader := v6TestConn(t, &bufferConn{Buffer: *bytes.NewBuffer(wire)}, mode, true)
			if _, err := reader.Read(make([]byte, 64)); err == nil {
				t.Fatal("accepted modified ciphertext")
			}
			wrong, err := StreamConnV6(&bufferConn{Buffer: *bytes.NewBuffer(raw.Bytes())}, []byte("wrong-password-12345"), mode)
			if err != nil {
				t.Fatal(err)
			}
			wrong.reply = true
			if _, err := wrong.Read(make([]byte, 64)); err == nil {
				t.Fatal("accepted wrong PSK")
			}
		})
	}
}

func TestSnellV6ConcurrentRecords(t *testing.T) {
	for _, mode := range []string{"default", "unshaped", "unsafe-raw"} {
		t.Run(mode, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			_ = a.SetDeadline(time.Now().Add(10 * time.Second))
			_ = b.SetDeadline(time.Now().Add(10 * time.Second))
			writer := v6TestConn(t, a, mode, true)
			reader := v6TestConn(t, b, mode, true)
			var writes sync.WaitGroup
			errs := make(chan error, 16)
			for i := 0; i < 16; i++ {
				writes.Add(1)
				go func(value byte) {
					defer writes.Done()
					_, err := writer.WritePacketFrame(bytes.Repeat([]byte{value}, 300))
					errs <- err
				}(byte(i))
			}
			go func() { writes.Wait(); _, _ = writer.Write(nil) }()
			got := make(map[byte]bool)
			for i := 0; i < 16; i++ {
				packet := make([]byte, 65535)
				n, err := reader.Read(packet)
				if err != nil || n != 300 {
					t.Fatalf("datagram %d = %d, %v", i, n, err)
				}
				if !bytes.Equal(packet[:n], bytes.Repeat(packet[:1], n)) || got[packet[0]] {
					t.Fatal("corrupt or duplicate datagram")
				}
				got[packet[0]] = true
			}
			for i := 0; i < 16; i++ {
				if err := <-errs; err != nil {
					t.Fatal(err)
				}
			}
			if _, err := reader.Read(make([]byte, 1)); err != io.EOF {
				t.Fatalf("EOF = %v", err)
			}
		})
	}
}

func TestSnellV6ClientIDHeader(t *testing.T) {
	raw := &bufferConn{}
	if err := WriteHeaderV6(raw, "example.com", 443, false, "client-7"); err != nil {
		t.Fatal(err)
	}
	want := []byte{1, 1, 8, 'c', 'l', 'i', 'e', 'n', 't', '-', '7', 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187}
	if !bytes.Equal(raw.Bytes(), want) {
		t.Fatalf("header = %x", raw.Bytes())
	}
	raw.Reset()
	if err := WriteHeaderV6(raw, "", 0, true, "id"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw.Bytes(), []byte{1, 6, 2, 'i', 'd'}) {
		t.Fatalf("UDP header = %x", raw.Bytes())
	}
}

func TestSnellV6HalfCloseKeepsResponseAlive(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(5 * time.Second))
	_ = b.SetDeadline(time.Now().Add(5 * time.Second))
	client := v6TestConn(t, a, "default", true)
	server := v6TestConn(t, b, "default", true)
	half, ok := any(client).(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("v6 stream must expose CloseWrite to relay")
	}
	finished := make(chan error, 1)
	go func() {
		if _, err := io.ReadAll(server); err != nil {
			finished <- err
			return
		}
		if _, err := server.Write([]byte("response after FIN")); err != nil {
			finished <- err
			return
		}
		_, err := server.Write(nil)
		finished <- err
	}()
	if err := half.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(client)
	if err != nil || string(got) != "response after FIN" {
		t.Fatalf("response = %q, %v", got, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}
