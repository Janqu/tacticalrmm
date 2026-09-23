package accounts

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestDjangoAuthenticationVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/auth_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Passwords []struct {
			Password, Encoded string
			Valid, Upgrade    bool
		}
		TOTP []struct {
			Secret, Token string
			At            int64
			Valid         bool
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Passwords) != 31 || len(vectors.TOTP) != 15 {
		t.Fatal("missing reference vectors")
	}
	for i, v := range vectors.Passwords {
		valid, upgrade := VerifyPassword(v.Password, v.Encoded)
		if valid != v.Valid || upgrade != v.Upgrade {
			t.Errorf("password vector %d: got valid=%v upgrade=%v; want %v %v", i, valid, upgrade, v.Valid, v.Upgrade)
		}
	}
	for i, v := range vectors.TOTP {
		if got := VerifyTOTP(v.Secret, v.Token, time.Unix(v.At, 0)); got != v.Valid {
			t.Errorf("TOTP vector %d: got %v; want %v", i, got, v.Valid)
		}
	}
}

func TestInvalidAuthenticationData(t *testing.T) {
	for _, encoded := range []string{
		"pbkdf2_sha256", "pbkdf2_sha256$0$salt$AAAA", "pbkdf2_sha256$9999999999999999999$salt$AAAA",
		"pbkdf2_sha256$600000$salt$!", "bcrypt_sha256$invalid",
		"scrypt$16384$salt$9999999999999999$1$AAAA",
		"argon2$argon2id$v=19$m=4294967295,t=2,p=8$c2FsdA$AAAA",
		"argon2$argon2id$v=19$m=102400,t=2,p=0$c2FsdA$AAAA",
	} {
		if valid, upgrade := VerifyPassword("password", encoded); valid || upgrade {
			t.Fatal("malformed password hash accepted")
		}
	}
	for _, secret := range []string{"", "!invalid", "========", "JBSWY3DPEHPK3PXP\n"} {
		if VerifyTOTP(secret, "367665", time.Unix(1700000010, 0)) {
			t.Fatal("invalid TOTP secret accepted")
		}
	}
}
