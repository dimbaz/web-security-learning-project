package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const (
	nonceLength = 12
	authLength  = 16
)

type EncryptedPayload struct {
	Nonce      []byte
	AuthTag    []byte
	Ciphertext []byte
}

func encrypt(plaintext []byte, key [32]byte) (EncryptedPayload, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return EncryptedPayload{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedPayload{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return EncryptedPayload{}, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, nil)
	return EncryptedPayload{Nonce: nonce, AuthTag: sealed[len(sealed)-16:], Ciphertext: sealed[:len(sealed)-16]}, nil
}

func decrypt(payload EncryptedPayload, key [32]byte) ([]byte, error) {
	if len(payload.Nonce) != nonceLength || len(payload.AuthTag) != authLength {
		return nil, fmt.Errorf("invalid nonce or authTag length")
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(payload.Ciphertext)+len(payload.AuthTag))
	sealed = append(sealed, payload.Ciphertext...)
	sealed = append(sealed, payload.AuthTag...)
	plaintext, err := aesgcm.Open(nil, payload.Nonce, sealed, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
