package outbound

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/metacubex/mihomo/common/structure"
)

func TestRealityRejectsInvalidXrayOptions(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	for _, field := range []string{"mldsa65-verify", "client-version"} {
		t.Run(field, func(t *testing.T) {
			option := RealityOptions{}
			decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
			if err := decoder.Decode(map[string]any{"public-key": publicKey, field: "invalid-test-value"}, &option); err != nil {
				t.Fatal(err)
			}
			_, err := option.Parse()
			if err == nil {
				t.Fatal("invalid option was silently ignored")
			}
			if strings.Contains(err.Error(), "invalid-test-value") {
				t.Fatal("error disclosed input")
			}
		})
	}
}

func TestRealityHybridDefaultAndLegacyOverride(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	for _, tc := range []struct {
		name  string
		value any
		want  bool
	}{
		{"omitted", nil, true}, {"enabled", true, true}, {"legacy", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]any{"public-key": publicKey}
			if tc.value != nil {
				input["support-x25519mlkem768"] = tc.value
			}
			var option RealityOptions
			decoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
			if err := decoder.Decode(input, &option); err != nil {
				t.Fatal(err)
			}
			config, err := option.Parse()
			if err != nil {
				t.Fatal(err)
			}
			if config.SupportX25519MLKEM768 != tc.want {
				t.Fatal("wrong hybrid default/override")
			}
		})
	}
}

func TestRealityClientVersionAndRequiredPublicKey(t *testing.T) {
	key, _ := ecdh.X25519().GenerateKey(rand.Reader)
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	config, err := (RealityOptions{PublicKey: publicKey, ClientVersion: "26.10.31", ShortID: "0001020304050607"}).Parse()
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientVersion == nil || *config.ClientVersion != [3]byte{26, 10, 31} {
		t.Fatal("client version not preserved")
	}
	if config.ShortID != [8]byte{0, 1, 2, 3, 4, 5, 6, 7} {
		t.Fatal("short ID not preserved")
	}
	for _, version := range []string{"26.10", "26.10.256", "-1.2.3", "26..3", "26.10.31.1"} {
		if _, err := (RealityOptions{PublicKey: publicKey, ClientVersion: version}).Parse(); err == nil {
			t.Fatal("invalid version accepted")
		}
	}
	for _, option := range []RealityOptions{{MLDSA65Verify: "invalid"}, {ShortID: "01"}, {ClientVersion: "26.10.31"}} {
		if _, err := option.Parse(); err == nil {
			t.Fatal("missing public key accepted")
		}
	}
}
