package main

import (
	"os"
	"testing"
)

func TestScriptRuntimeConfig(t *testing.T) {
	// An explicit empty Deno policy must not regain the permissive default.
	t.Setenv("DENO_DEFAULT_PERMISSIONS", "")
	t.Setenv("NUSHELL_ENABLE_CONFIG", "true")
	config, err := scriptRuntimeConfig()
	if err != nil || !config.NushellEnableConfig || config.DenoDefaultPermissions == nil || *config.DenoDefaultPermissions != "" {
		t.Fatal("explicit runtime settings were not preserved")
	}
	t.Setenv("NUSHELL_ENABLE_CONFIG", "invalid")
	if _, err := scriptRuntimeConfig(); err == nil {
		t.Fatal("accepted invalid Nushell configuration")
	}
	if err := os.Unsetenv("NUSHELL_ENABLE_CONFIG"); err != nil {
		t.Fatal(err)
	}
	if err := os.Unsetenv("DENO_DEFAULT_PERMISSIONS"); err != nil {
		t.Fatal(err)
	}
	config, err = scriptRuntimeConfig()
	if err != nil || config.NushellEnableConfig || config.DenoDefaultPermissions != nil {
		t.Fatal("missing settings did not retain defaults")
	}
}
