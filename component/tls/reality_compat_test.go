//go:build go1.27

package tls

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	utls "github.com/metacubex/utls"
	"testing"
	"time"
)

func TestRealitySessionIDMatchesXrayLayout(t *testing.T) {
	version := [3]byte{26, 10, 31}
	config := &RealityConfig{ClientVersion: &version, ShortID: [8]byte{0, 1, 2, 3, 4, 5, 6, 7}}
	for _, unix := range []int64{1700000000, (1 << 32) + 100} {
		id := realitySessionID(time.Unix(unix, 0), config)
		if [3]byte{id[0], id[1], id[2]} != version || id[3] != 0 {
			t.Fatal("version/reserved layout differs")
		}
		if binary.BigEndian.Uint32(id[4:8]) != uint32(unix) {
			t.Fatal("timestamp layout differs")
		}
		for i, v := range config.ShortID {
			if id[8+i] != v {
				t.Fatal("short ID differs")
			}
		}
		for _, v := range id[16:] {
			if v != 0 {
				t.Fatal("AEAD tag region was not zeroed")
			}
		}
	}
	legacy := realitySessionID(time.Unix(1, 0), &RealityConfig{})
	if [3]byte{legacy[0], legacy[1], legacy[2]} != [3]byte{1, 8, 2} {
		t.Fatal("legacy version default changed")
	}
}

func TestRealityMLDSA65AuthenticatesXrayTranscript(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	verify, err := NewRealityMLDSA65Verifier(key.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	authKey := []byte("public-test-auth-key-32-bytes-long")
	client, server := []byte("client-hello-wire"), []byte("server-hello-wire")
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	cert := &x509.Certificate{PublicKey: pub, Signature: h.Sum(nil)}
	h.Write(client)
	h.Write(server)
	sig, err := key.Sign(nil, h.Sum(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	cert.Extensions = []pkix.Extension{{Value: sig}}
	if !authenticateRealityCertificate(cert, authKey, client, server, verify) {
		t.Fatal("valid Xray transcript rejected")
	}
	if !authenticateRealityCertificate(cert, authKey, nil, nil, nil) {
		t.Fatal("legacy HMAC certificate rejected")
	}
	if authenticateRealityCertificate(cert, authKey, []byte("wrong"), server, verify) {
		t.Fatal("wrong transcript accepted")
	}
	if authenticateRealityCertificate(cert, []byte("wrong"), client, server, verify) {
		t.Fatal("wrong auth key accepted")
	}
	cert.Extensions[0].Value[0] ^= 1
	if authenticateRealityCertificate(cert, authKey, client, server, verify) {
		t.Fatal("tampered signature accepted")
	}
	cert.Extensions = nil
	if authenticateRealityCertificate(cert, authKey, client, server, verify) {
		t.Fatal("missing MLDSA signature accepted")
	}
	if authenticateRealityCertificate(nil, authKey, client, server, verify) {
		t.Fatal("nil certificate accepted")
	}
	if _, err := NewRealityMLDSA65Verifier([]byte("short")); err == nil {
		t.Fatal("invalid key accepted")
	}
}

func TestRealityEmptyCertificateFailsWithoutPanic(t *testing.T) {
	if err := new(realityVerifier).VerifyConnection(utls.ConnectionState{}); err == nil {
		t.Fatal("empty certificate accepted")
	}
}
