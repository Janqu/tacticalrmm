package accounts

import (
	"encoding/base32"
	"testing"
)

func TestTOTPProvisioningMatchesPyOTP(t *testing.T) {
	// Produced by pyotp.TOTP(secret).provisioning_uri(username, issuer_name=issuer).
	want := "otpauth://totp/rmm.example.com%3A8443:a%2Bb%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=rmm.example.com%3A8443"
	if got := TOTPProvisioningURI("JBSWY3DPEHPK3PXP", "a+b@example.com", "rmm.example.com:8443"); got != want {
		t.Fatalf("got %s; want %s", got, want)
	}
	secret, err := GenerateTOTPKey()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base32.StdEncoding.DecodeString(secret)
	if err != nil || len(secret) != 32 || len(decoded) != 20 {
		t.Fatal("invalid TOTP secret")
	}
}
