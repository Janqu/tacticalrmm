package httpapi

import "testing"

func TestScriptCollectorValue(t *testing.T) {
	for _, tc := range []struct {
		input string
		all   bool
		want  string
	}{
		{"  first\n last \n", true, "first\n last"},
		{"  first\n last \n", false, "last"},
		{"\x1c\u0085\u00a0 text \x1f", true, "text"},
		{" a\r\nb\r\n", false, "b"},
		{" a\rb ", false, "a\rb"},
		{" \n ", false, ""},
		{" a, b,, ", true, "a, b,,"},
	} {
		got, err := scriptCollectorValue(tc.input, tc.all)
		if err != nil || got != tc.want {
			t.Fatalf("%q all=%v: %q %v", tc.input, tc.all, got, err)
		}
	}
	for _, reply := range []any{nil, true, 1, []any{}, map[string]any{}, "bad\x00value"} {
		if _, err := scriptCollectorValue(reply, true); err == nil {
			t.Fatalf("accepted %#v", reply)
		}
	}
}
