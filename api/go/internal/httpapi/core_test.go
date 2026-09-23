package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestMaskToken(t *testing.T) {
	for in, want := range map[string]string{"": "", "abc": "•••", "abcd": "••••", "abcdef": "••cdef", "äöüßxy": "••üßxy"} {
		if got := maskToken(in); got != want {
			t.Errorf("maskToken(%q) = %q, want %q", in, got, want)
		}
	}
	if maskToken(nil) != nil {
		t.Error("null token must stay null")
	}
}

func TestListSpec(t *testing.T) {
	value, problem := listSpec(true)(json.RawMessage(`["a@example.com", null, " "]`))
	if problem != nil || !reflect.DeepEqual(value, []any{"a@example.com", nil, ""}) {
		t.Fatalf("got %v %v", value, problem)
	}
	_, problem = listSpec(true)(json.RawMessage(`["a@example.com", "nope"]`))
	if !reflect.DeepEqual(problem, map[string][]string{"1": {"Enter a valid email address."}}) {
		t.Fatalf("got %v", problem)
	}
	for raw, want := range map[string]string{`"x"`: `Expected a list of items but got type "str".`, `null`: "This field may not be null."} {
		if _, problem = listSpec(false)(json.RawMessage(raw)); !reflect.DeepEqual(problem, []string{want}) {
			t.Fatalf("%s: got %v", raw, problem)
		}
	}
}

func TestSignedIntSpec(t *testing.T) {
	for raw, want := range map[string]int64{"5": 5, "-3": -3} {
		if got, problem := signedIntSpec(json.RawMessage(raw)); problem != nil || got != want {
			t.Fatalf("%s: %v %v", raw, got, problem)
		}
	}
	if _, problem := signedIntSpec(json.RawMessage("-2147483649")); problem == nil {
		t.Fatal("out of range accepted")
	}
	if _, problem := signedIntSpec(json.RawMessage(`"x"`)); problem == nil {
		t.Fatal("string accepted")
	}
}

func TestRedactedCopyKeepsOriginal(t *testing.T) {
	original := map[string]any{"value": "secret", "empty": "", "name": "n"}
	got := redactedCopy(original, []string{"value", "empty"})
	if got["value"] != "[redacted]" || got["empty"] != "" || original["value"] != "secret" {
		t.Fatalf("got %v / %v", got, original)
	}
}

func TestCoreRoutesRequireAuthentication(t *testing.T) {
	app := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{})
	for _, r := range [][2]string{{"GET", "/core/settings/"}, {"PUT", "/core/settings/"}, {"GET", "/core/urlaction/"}, {"DELETE", "/core/urlaction/1/"},
		{"POST", "/core/keystore/"}, {"PUT", "/core/keystore/1/"}, {"GET", "/core/codesign/"}, {"DELETE", "/core/codesign/"}} {
		response, err := app.Test(httptest.NewRequest(r[0], r[1], nil))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 401 {
			t.Errorf("%s %s = %d", r[0], r[1], response.StatusCode)
		}
	}
}
