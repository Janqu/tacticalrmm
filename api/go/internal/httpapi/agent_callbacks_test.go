package httpapi

import "testing"

func TestChocoInstallSucceeded(t *testing.T) {
	for _, tc := range []struct {
		name, output string
		want         bool
	}{
		{"7zip", "The install of 7zip was successful. Installed 1 package.", true},
		{"Firefox", "FIREFOX already INSTALLED; use --force to reinstall", true},
		{"7zip", "The install of other was successful. Installed 1 package.", false},
		{"7zip", "7zip installed", false},
		{"7zip", "7zip already installed, reinstall", false},
		{"7zip", "", false},
		{"Ä-package", "INSTALL OF ä-PACKAGE WAS SUCCESSFUL INSTALLED", true},
	} {
		if got := chocoInstallSucceeded(tc.name, tc.output); got != tc.want {
			t.Fatalf("%#v got%v", tc, got)
		}
	}
}
