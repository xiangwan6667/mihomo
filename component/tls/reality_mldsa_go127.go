//go:build go1.27

package tls

import "crypto/mldsa"

func NewRealityMLDSA65Verifier(encoded []byte) (func(message, signature []byte) bool, error) {
	key, err := mldsa.NewPublicKey(mldsa.MLDSA65(), encoded)
	if err != nil {
		return nil, err
	}
	return func(message, signature []byte) bool {
		return mldsa.Verify(key, message, signature, nil) == nil
	}, nil
}
