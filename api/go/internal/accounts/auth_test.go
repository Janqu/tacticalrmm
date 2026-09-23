package accounts

import (
	"testing"
)

func TestKnoxDigest(t *testing.T) {
	// Python: hashlib.sha512(bytes.fromhex("00010203")).hexdigest()
	want := "4ec54b09e2b209ddb9a678522bb451740c513f488cb27a0883630718571745141920036aebdb78c0b4cd783a4a6eecc937a40c6104e427512d709a634b412f60"
	got, err := TokenDigest("00010203")
	if err != nil || got != want {
		t.Fatalf("digest = %q, %v; want %q", got, err, want)
	}
	for _, invalid := range []string{"", "0", "zz", "not-a-token"} {
		if _, err := TokenDigest(invalid); err == nil {
			t.Errorf("accepted %q", invalid)
		}
	}
}

func TestPermissionsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name       string
		principal  Principal
		permission string
		want       bool
	}{
		{"no role", Principal{}, "can_list_accounts", false},
		{"root", Principal{User: User{IsSuperuser: true}}, "can_list_accounts", true},
		{"super role", Principal{Role: &Role{IsSuperuser: true}}, "can_list_accounts", true},
		{"allowed", Principal{Role: &Role{CanListAccounts: true}}, "can_list_accounts", true},
		{"read not write", Principal{Role: &Role{CanListAccounts: true}}, "can_manage_accounts", false},
		{"unknown", Principal{Role: &Role{CanListAccounts: true}}, "unknown", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.principal.Can(test.permission); got != test.want {
				t.Fatalf("Can = %v, want %v", got, test.want)
			}
		})
	}
}
