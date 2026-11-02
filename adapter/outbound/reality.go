package outbound

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	tlsC "github.com/metacubex/mihomo/component/tls"
)

type RealityOptions struct {
	PublicKey     string `proxy:"public-key"`
	ShortID       string `proxy:"short-id,omitempty"`
	MLDSA65Verify string `proxy:"mldsa65-verify,omitempty"`
	ClientVersion string `proxy:"client-version,omitempty"`

	SupportX25519MLKEM768 *bool `proxy:"support-x25519mlkem768,omitempty"`
}

func (o RealityOptions) Parse() (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" {
		config := new(tlsC.RealityConfig)
		config.SupportX25519MLKEM768 = o.SupportX25519MLKEM768 == nil || *o.SupportX25519MLKEM768
		if o.MLDSA65Verify != "" {
			key, err := base64.RawURLEncoding.DecodeString(o.MLDSA65Verify)
			if err != nil || len(key) != 1952 {
				return nil, errors.New("invalid REALITY ML-DSA-65 verification key")
			}
			config.MLDSA65Verify, err = tlsC.NewRealityMLDSA65Verifier(key)
			if err != nil {
				return nil, err
			}
		}
		if o.ClientVersion != "" {
			if len(o.ClientVersion) > 11 {
				return nil, errors.New("invalid REALITY client version")
			}
			parts := strings.Split(o.ClientVersion, ".")
			if len(parts) != 3 {
				return nil, errors.New("invalid REALITY client version")
			}
			version := new([3]byte)
			for i, part := range parts {
				value, err := strconv.ParseUint(part, 10, 8)
				if err != nil {
					return nil, errors.New("invalid REALITY client version")
				}
				version[i] = byte(value)
			}
			config.ClientVersion = version
		}

		const x25519ScalarSize = 32
		publicKey, err := base64.RawURLEncoding.DecodeString(o.PublicKey)
		if err != nil || len(publicKey) != x25519ScalarSize {
			return nil, errors.New("invalid REALITY public key")
		}
		config.PublicKey, err = ecdh.X25519().NewPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("fail to create REALITY public key: %w", err)
		}

		n := hex.DecodedLen(len(o.ShortID))
		if n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short id")
		}
		n, err = hex.Decode(config.ShortID[:], []byte(o.ShortID))
		if err != nil || n > tlsC.RealityMaxShortIDLen {
			return nil, errors.New("invalid REALITY short ID")
		}

		return config, nil
	}
	if o.ShortID != "" || o.MLDSA65Verify != "" || o.ClientVersion != "" {
		return nil, errors.New("REALITY public key is required")
	}
	return nil, nil
}

func (o RealityOptions) ParseForNetwork(network string) (*tlsC.RealityConfig, error) {
	if o.PublicKey != "" || o.ShortID != "" || o.MLDSA65Verify != "" || o.ClientVersion != "" {
		switch strings.ToLower(network) {
		case "", "tcp", "raw", "grpc", "xhttp", "splithttp":
		default:
			return nil, errors.New("REALITY requires TCP, XHTTP or gRPC transport")
		}
	}
	return o.Parse()
}
