package accounts

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/text/unicode/norm"
)

// VerifyTOTP matches PyOTP's six digits, 30-second step and the login view's
// +/-10-step window. An absent secret always fails, including during setup.
func VerifyTOTP(secret, token string, at time.Time) bool {
	if secret == "" || len(secret) > 256 || strings.ContainsAny(secret, "\r\n") || len(token) > 64 || at.Unix() < 0 {
		return false
	}
	secret = strings.ToUpper(secret)
	secret += strings.Repeat("=", (8-len(secret)%8)%8)
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil || len(key) == 0 {
		return false
	}
	token = norm.NFKC.String(token)
	if len(token) != 6 {
		return false
	}
	matched := 0
	for offset := int64(-10); offset <= 10; offset++ {
		counter := at.Unix()/30 + offset
		if counter < 0 {
			continue
		}
		var input [8]byte
		binary.BigEndian.PutUint64(input[:], uint64(counter))
		mac := hmac.New(sha1.New, key)
		_, _ = mac.Write(input[:])
		digest := mac.Sum(nil)
		start := digest[len(digest)-1] & 15
		code := (binary.BigEndian.Uint32(digest[start:start+4]) & 0x7fffffff) % 1000000
		matched |= subtle.ConstantTimeCompare([]byte(token), []byte(fmt.Sprintf("%06d", code)))
	}
	return matched == 1
}

func GenerateTOTPKey() (string, error) {
	var secret [20]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret[:]), nil
}

// Match PyOTP's default SHA-1 / 6-digit / 30-second provisioning URI, including
// quoting and parameter order (the frontend receives the entire URI as a string).
func TOTPProvisioningURI(secret, username, issuer string) string {
	quote := func(value string) string {
		return strings.ReplaceAll(strings.ReplaceAll(url.QueryEscape(value), "+", "%20"), "%2F", "/")
	}
	return "otpauth://totp/" + quote(issuer) + ":" + quote(username) + "?secret=" + quote(secret) + "&issuer=" + strings.ReplaceAll(url.QueryEscape(issuer), "+", "%20")
}
