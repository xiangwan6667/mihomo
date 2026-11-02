//go:build !go1.27

package tls

import "errors"

func NewRealityMLDSA65Verifier(encoded []byte) (func(message, signature []byte) bool, error) {
	return nil, errors.New("REALITY ML-DSA-65 verification requires Go 1.27 or newer")
}
