package passwords

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	MaxLength   = 128
	aMemory     = 19 * 1024
	aIterations = 2
	aLane       = 1
	aLength     = 32
)

func Hash(password string) (string, error) {
	if utf8.RuneCountInString(password) > MaxLength {
		return "", fmt.Errorf("password must not exceed %d characters", MaxLength)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derivedKey := argon2.IDKey([]byte(password), salt, aIterations, aMemory, aLane, aLength)
	argon2idHash := argon2idHash{
		version:     int(argon2.Version),
		memoryKiB:   uint32(aMemory),
		iterations:  uint32(aIterations),
		parallelism: uint8(aLane),
		salt:        salt,
		derivedKey:  derivedKey,
	}
	passwordHash := encodeArgon2idHash(argon2idHash)
	return passwordHash, nil
}

func Verify(password, encodedHash string) bool {
	if utf8.RuneCountInString(password) > MaxLength {
		return false
	}
	if len(encodedHash) == 64 {
		expectedHash, ok := decodeLegacyHash(encodedHash)
		if !ok {
			return false
		}
		candidateHash := sha256.Sum256([]byte(password))
		sha256validity := subtle.ConstantTimeCompare(candidateHash[:], expectedHash) == 1
		return sha256validity
	}
	if strings.HasPrefix(encodedHash, "$argon2id$") {
		argon2IdHash, ok := parseArgon2idHash(encodedHash)
		if !ok || argon2IdHash.version != argon2.Version {
			return false
		}
		derivedKey := argon2.IDKey([]byte(password), argon2IdHash.salt, argon2IdHash.iterations, argon2IdHash.memoryKiB, argon2IdHash.parallelism, uint32(len(argon2IdHash.derivedKey)))
		argonValidity := subtle.ConstantTimeCompare(derivedKey, argon2IdHash.derivedKey) == 1
		return argonValidity
	}
	return false
}

func NeedsRehash(encodedHash string) bool {
	if len(encodedHash) == 64 {
		return true
	}
	if strings.HasPrefix(encodedHash, "$argon2id$") {
		argon2IdHash, ok := parseArgon2idHash(encodedHash)
		if !ok {
			return false
		}
		if argon2IdHash.version != argon2.Version || argon2IdHash.memoryKiB != aMemory || argon2IdHash.iterations != aIterations || argon2IdHash.parallelism != aLane || len(argon2IdHash.derivedKey) != aLength {
			return true
		}
	}
	return false
}
