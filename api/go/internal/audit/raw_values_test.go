package audit

import (
	"strings"
	"testing"
)

func TestBoundedAuditString(t *testing.T) {
	for _, value := range []any{"echo hello", map[string]any{"cmd": "hello"}, nil} {
		got := boundedValue(value)
		switch want := value.(type) {
		case string:
			if got != want {
				t.Fatal("audit string shape changed")
			}
		case nil:
			if got != nil {
				t.Fatal("nil shape changed")
			}
		case map[string]any:
			if got.(map[string]any)["cmd"] != "hello" {
				t.Fatal("map changed")
			}
		}
	}
	// Non-ASCII costs six bytes in Django json.dumps, not two UTF-8 bytes.
	if _, ok := boundedValue(strings.Repeat("ü", 90000)).(map[string]any); !ok {
		t.Fatal("unicode audit limit not applied")
	}
	if got, ok := boundedValue(strings.Repeat("x", 512*1024-2)).(string); !ok || len(got) != 512*1024-2 {
		t.Fatal("exact audit limit rejected")
	}
}
