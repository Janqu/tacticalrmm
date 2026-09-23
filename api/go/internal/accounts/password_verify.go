package accounts

import (
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// VerifyPassword accepts Django's five default hashers. Upgrade is true only
// after a successful check; callers must persist PasswordHash before login.
// An empty encoding also performs default hashing work for unknown users.
func VerifyPassword(password, encoded string) (valid, upgrade bool) {
	parts := strings.Split(encoded, "$")
	var derived, expected []byte
	var err error
	needsUpgrade := true
	iterations := 0
	parsed := false
	switch parts[0] {
	case "pbkdf2_sha256", "pbkdf2_sha1":
		if len(parts) != 4 || parts[2] == "" {
			break
		}
		iterations, err = strconv.Atoi(parts[1])
		// Bound corrupted database parameters before spending CPU or memory.
		if err != nil || iterations < 1 || iterations > 10000000 || parts[1] != strconv.Itoa(iterations) {
			break
		}
		digest := sha256.New
		if parts[0] == "pbkdf2_sha1" {
			digest = sha1.New
		}
		expected, err = base64.StdEncoding.Strict().DecodeString(parts[3])
		if err != nil || len(expected) != digest().Size() {
			break
		}
		derived, err = pbkdf2.Key(digest, password, []byte(parts[2]), iterations, digest().Size())
		parsed = err == nil
		needsUpgrade = parts[0] != "pbkdf2_sha256" || iterations != PasswordIterations || utf8.RuneCountInString(parts[2]) < 22
	case "bcrypt_sha256":
		raw := strings.TrimPrefix(encoded, "bcrypt_sha256$")
		cost, costErr := bcrypt.Cost([]byte(raw))
		if costErr != nil || cost > 16 {
			break
		}
		digest := sha256.Sum256([]byte(password))
		err = bcrypt.CompareHashAndPassword([]byte(raw), []byte(hex.EncodeToString(digest[:])))
		return err == nil, err == nil
	case "scrypt":
		if len(parts) != 6 || parts[2] == "" {
			break
		}
		n, e1 := strconv.Atoi(parts[1])
		r, e2 := strconv.Atoi(parts[3])
		p, e3 := strconv.Atoi(parts[4])
		if parts[1] != strconv.Itoa(n) || parts[3] != strconv.Itoa(r) || parts[4] != strconv.Itoa(p) {
			break
		}
		// At most 256 MiB and bounded CPU work, including on malformed hashes.
		if e1 != nil || e2 != nil || e3 != nil || n < 2 || n > 1<<20 || n&(n-1) != 0 || r < 1 || r > 32 || p < 1 || p > 16 || int64(n)*int64(r) > 1<<21 || int64(n)*int64(r)*int64(p) > 1<<23 {
			break
		}
		expected, err = base64.StdEncoding.Strict().DecodeString(parts[5])
		if err != nil || len(expected) != 64 {
			break
		}
		derived, err = scrypt.Key([]byte(password), []byte(parts[2]), n, r, p, 64)
		parsed = err == nil
	case "argon2":
		if len(parts) != 6 || parts[2] != "v=19" || (parts[1] != "argon2id" && parts[1] != "argon2i") {
			break
		}
		var memory, rounds uint32
		var threads uint8
		if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &rounds, &threads); err != nil || parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", memory, rounds, threads) {
			break
		}
		if threads == 0 || threads > 32 || memory < 8*uint32(threads) || memory > 256*1024 || rounds < 1 || rounds > 10 {
			break
		}
		salt, saltErr := base64.RawStdEncoding.Strict().DecodeString(parts[4])
		expected, err = base64.RawStdEncoding.Strict().DecodeString(parts[5])
		if saltErr != nil || len(salt) < 8 || err != nil || len(expected) < 4 || len(expected) > 64 {
			break
		}
		derive := argon2.IDKey
		if parts[1] == "argon2i" {
			derive = argon2.Key
		}
		derived = derive([]byte(password), salt, rounds, memory, threads, uint32(len(expected)))
		parsed = true
	}
	if !parsed {
		// Django also burns one default hash for unusable/unknown encodings.
		_, _ = pbkdf2.Key(sha256.New, password, []byte("unknown-password-salt"), PasswordIterations, sha256.Size)
		return false, false
	}
	valid = hmac.Equal(derived, expected)
	if !valid && parts[0] == "pbkdf2_sha256" && iterations < PasswordIterations {
		_, _ = pbkdf2.Key(sha256.New, password, []byte(parts[2]), PasswordIterations-iterations, sha256.Size)
	}
	return valid, valid && needsUpgrade
}
