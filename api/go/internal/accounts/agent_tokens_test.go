package accounts

import "testing"

func TestAgentTokenHeader(t *testing.T) {
	for _, input := range []string{"Token abc", "tOkEn\tabc", " Token  abc "} {
		key, err := agentTokenHeader(input)
		if err != nil || key != "abc" {
			t.Fatalf("%q got%q %v", input, key, err)
		}
	}
	for _, input := range []string{"", "Bearer abc", "Token", "Token a b", "Token \xff"} {
		if _, err := agentTokenHeader(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
	key, err := agentTokenHeader("Token abc\u00a0def")
	if err != nil || key != "abc\u00a0def" {
		t.Fatal("must match DRF bytes whitespace semantics")
	}
}
