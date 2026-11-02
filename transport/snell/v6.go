package snell

import (
	"errors"
	"io"
	"net"
	"sync"
)

const (
	saltLen         = v4SaltSize
	nonceLen        = v4NonceSize
	headerVersion   = 4
	headerPlainLen  = v4HeaderPlainSize
	aeadTagLen      = 16
	headerCipherLen = v4HeaderCipherSize
)

type v6Conn struct {
	net.Conn
	psk         []byte
	mode        Mode
	profile     *Profile
	reader      snellReader
	writer      snellWriter
	readMu      sync.Mutex
	writeMu     sync.Mutex
	readErr     error
	writeErr    error
	writeClosed bool
}

// StreamConnV6 uses a distinct record layer; v6 is not backward-compatible with v4.
func StreamConnV6(conn net.Conn, psk []byte, modeName string) (*Snell, error) {
	if len(psk) < 12 || len(psk) > 255 {
		return nil, errors.New("snell: v6 psk length must be 12..255 bytes")
	}
	mode, err := ParseMode(modeName)
	if err != nil {
		return nil, err
	}
	c := &v6Conn{Conn: conn, psk: append([]byte(nil), psk...), mode: mode}
	if mode == ModeDefault {
		c.profile = NewProfile(c.psk)
	}
	c.reader = newV6Reader(conn, mode, c.psk, c.profile)
	return &Snell{Conn: c}, nil
}

type v6RecordSink struct{ io.Writer }

func (w v6RecordSink) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n, err := w.Writer.Write(p)
		if n < 0 || n > len(p) {
			return total, io.ErrShortWrite
		}
		total += n
		p = p[n:]
		if err != nil {
			return total, err
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}

func (c *v6Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	n, err := c.reader.Read(p)
	if err != nil {
		c.readErr = err
	}
	return n, err
}

func (c *v6Conn) initWriter() error {
	if c.writeErr != nil {
		return c.writeErr
	}
	if c.writeClosed {
		return io.ErrClosedPipe
	}
	if c.writer == nil {
		c.writer, c.writeErr = newV6Writer(v6RecordSink{c.Conn}, c.mode, c.psk, c.profile)
	}
	return c.writeErr
}

func (c *v6Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.initWriter(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, c.closeWrite()
	}
	n, err := c.writer.Write(p)
	c.writeErr = err
	return n, err
}

func (c *v6Conn) WritePacketFrame(p []byte) (int, error) {
	if len(p) == 0 || len(p) > maxPayloadV6 {
		return 0, errV6PayloadTooLarge
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.initWriter(); err != nil {
		return 0, err
	}
	c.writeErr = c.writer.writeDatagram(p)
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *v6Conn) closeWrite() error {
	c.writeClosed = true
	c.writeErr = c.writer.writeZeroChunk()
	return c.writeErr
}

func (c *v6Conn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return c.writeErr
	}
	if err := c.initWriter(); err != nil {
		return err
	}
	return c.closeWrite()
}

type invalidSnellConn struct {
	net.Conn
	err error
}

func (c *invalidSnellConn) Read([]byte) (int, error)  { return 0, c.err }
func (c *invalidSnellConn) Write([]byte) (int, error) { return 0, c.err }

func WriteHeaderV6(conn net.Conn, host string, port uint, udp bool, clientID string) error {
	if len(clientID) > 255 {
		return errors.New("snell: client-id exceeds 255 bytes")
	}
	if !udp && (len(host) == 0 || len(host) > 255 || port > 65535) {
		return errors.New("snell: invalid v6 destination")
	}
	command := CommandConnect
	if udp {
		command = CommandUDP
	}
	header := []byte{Version, command, byte(len(clientID))}
	header = append(header, clientID...)
	if !udp {
		header = append(header, byte(len(host)))
		header = append(header, host...)
		header = append(header, byte(port>>8), byte(port))
	}
	_, err := (v6RecordSink{conn}).Write(header)
	return err
}

func minV6(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxV6(a, b int) int {
	if a > b {
		return a
	}
	return b
}
