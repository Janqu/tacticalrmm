package accounts

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

// Match Django 4.2's default PBKDF2PasswordHasher, including its salt entropy.
const PasswordIterations = 600000

func PasswordHash(password *string) (string, error) {
	if password == nil {
		suffix, err := randomString(40)
		if err != nil {
			return "", err
		}
		return "!" + suffix, nil
	}
	salt, err := randomString(22)
	if err != nil {
		return "", err
	}
	key, err := pbkdf2.Key(sha256.New, *password, []byte(salt), PasswordIterations, sha256.Size)
	if err != nil {
		return "", fmt.Errorf("derive password hash: %w", err)
	}
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", PasswordIterations, salt, base64.StdEncoding.EncodeToString(key)), nil
}

func GenerateAPIKey() (string, error) {
	value, err := randomString(32)
	return strings.ToUpper(value), err
}

func randomString(length int) (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	value := make([]byte, length)
	limit := big.NewInt(int64(len(alphabet)))
	for i := range value {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return "", fmt.Errorf("generate secure random string: %w", err)
		}
		value[i] = alphabet[n.Int64()]
	}
	return string(value), nil
}
