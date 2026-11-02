package tls

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"

	"github.com/metacubex/http"
	"github.com/metacubex/randv2"
	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

const RealityMaxShortIDLen = 8

type RealityConfig struct {
	PublicKey     *ecdh.PublicKey
	ShortID       [RealityMaxShortIDLen]byte
	ClientVersion *[3]byte
	MLDSA65Verify func(message, signature []byte) bool

	SupportX25519MLKEM768 bool
}

func GetRealityConn(ctx context.Context, conn net.Conn, fingerprint UClientHelloID, serverName string, realityConfig *RealityConfig) (net.Conn, error) {
	for retry := 0; ; retry++ {
		verifier := &realityVerifier{
			serverName:    serverName,
			mldsa65Verify: realityConfig.MLDSA65Verify,
		}
		uConfig := &utls.Config{
			Time:                   ntp.Now,
			ServerName:             serverName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
			VerifyConnection:       verifier.VerifyConnection,
		}

		uConn := utls.UClient(conn, uConfig, fingerprint)
		verifier.UConn = uConn
		err := uConn.BuildHandshakeState()
		if err != nil {
			return nil, err
		}

		if !realityConfig.SupportX25519MLKEM768 { // for X25519MLKEM768 does not work properly with the old reality server
			err = BuildRemovedX25519MLKEM768HandshakeState(uConn)
			if err != nil {
				return nil, err
			}
		}

		hello := uConn.HandshakeState.Hello
		if len(hello.Raw) < 71 || hello.Raw[38] != 32 || len(hello.Random) != 32 {
			return nil, errors.New("REALITY fingerprint requires a 32-byte session ID")
		}
		hello.SessionId = make([]byte, 32)
		rawSessionID := hello.Raw[39 : 39+32] // the location of session ID
		for i := range rawSessionID {         // https://github.com/golang/go/issues/5373
			rawSessionID[i] = 0
		}

		sessionID := realitySessionID(ntp.Now(), realityConfig)
		copy(hello.SessionId, sessionID[:])

		keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
		if keyShareKeys == nil {
			if retry > 2 {
				return nil, errors.New("nil keyShareKeys")
			}
			continue // retry
		}
		ecdheKey := keyShareKeys.Ecdhe
		if ecdheKey == nil {
			ecdheKey = keyShareKeys.MlkemEcdhe
		}
		if ecdheKey == nil {
			if retry > 2 {
				return nil, errors.New("nil ecdheKey")
			}
			continue // retry
		}
		authKey, err := ecdheKey.ECDH(realityConfig.PublicKey)
		if err != nil {
			return nil, err
		}
		if authKey == nil {
			return nil, errors.New("nil auth_key")
		}
		verifier.authKey = authKey
		_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
		if err != nil {
			return nil, err
		}
		aesBlock, _ := aes.NewCipher(authKey)
		aeadCipher, _ := cipher.NewGCM(aesBlock)
		aeadCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
		copy(hello.Raw[39:], hello.SessionId)

		err = uConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}

		log.Debugln("REALITY Authentication: %v, AEAD: %T", verifier.verified, aeadCipher)

		if !verifier.verified {
			go realityClientFallback(uConn, uConfig.ServerName, fingerprint)
			return nil, errors.New("REALITY authentication failed")
		}

		return uConn, nil
	}
}

func realityClientFallback(uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	// use h2c mode to disallow the net/http fallback to http1.1
	//
	// Note that this usage is only applicable to our own net/http fork.
	// The standard library also needs to mask the tls.Conn type for the conn returned by DialTLSContext
	// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	client := http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return uConn, nil
			},
			Protocols: protocols,
		},
	}
	request, err := http.NewRequest("GET", "https://"+serverName, nil)
	if err != nil {
		return
	}
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", randv2.IntN(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	time.Sleep(time.Duration(5+randv2.IntN(10)) * time.Second)
	response.Body.Close()
	client.CloseIdleConnections()
}

type realityVerifier struct {
	*utls.UConn
	serverName    string
	authKey       []byte
	verified      bool
	mldsa65Verify func(message, signature []byte) bool
}

func (c *realityVerifier) VerifyConnection(state utls.ConnectionState) error {
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return errors.New("REALITY server sent no certificate")
	}
	if c.HandshakeState.ServerHello != nil {
		log.Debugln("REALITY localAddr: %v is using X25519MLKEM768 for TLS' communication: %v", c.RemoteAddr(), c.HandshakeState.ServerHello.ServerShare.Group == utls.X25519MLKEM768)
	}
	var clientHello, serverHello []byte
	if c.HandshakeState.Hello != nil {
		clientHello = c.HandshakeState.Hello.Raw
	}
	if c.HandshakeState.ServerHello != nil {
		serverHello = c.HandshakeState.ServerHello.Raw
	}
	if authenticateRealityCertificate(certs[0], c.authKey, clientHello, serverHello, c.mldsa65Verify) {
		c.verified = true
		return nil
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
		CurrentTime:   ntp.Now(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}

func realitySessionID(now time.Time, config *RealityConfig) (sessionID [32]byte) {
	version := [3]byte{1, 8, 2}
	if config.ClientVersion != nil {
		version = *config.ClientVersion
	}
	copy(sessionID[:3], version[:])
	binary.BigEndian.PutUint32(sessionID[4:8], uint32(now.Unix()))
	copy(sessionID[8:16], config.ShortID[:])
	return
}

func authenticateRealityCertificate(cert *x509.Certificate, authKey, clientHello, serverHello []byte, verify func(message, signature []byte) bool) bool {
	if cert == nil {
		return false
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	if !hmac.Equal(h.Sum(nil), cert.Signature) {
		return false
	}
	if verify == nil {
		return true
	}
	if len(cert.Extensions) == 0 || len(clientHello) == 0 || len(serverHello) == 0 {
		return false
	}
	h.Write(clientHello)
	h.Write(serverHello)
	return verify(h.Sum(nil), cert.Extensions[0].Value)
}
