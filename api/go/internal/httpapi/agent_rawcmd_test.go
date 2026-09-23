package httpapi

import (
	"encoding/json"
	"testing"
)

func TestParseRawCommand(t *testing.T) {
	base := func() map[string]json.RawMessage {
		return map[string]json.RawMessage{"cmd": json.RawMessage(`" echo ü "`), "shell": json.RawMessage(`"cmd"`), "timeout": json.RawMessage(`30`), "run_as_user": json.RawMessage(`false`)}
	}
	input := base()
	got, err := parseRawCommand(input)
	if err != nil || got.Command != " echo ü " || got.Shell != "cmd" || got.Timeout != 30 || got.RunAsUser {
		t.Fatalf("got%#v %v", got, err)
	}
	input["shell"], input["custom_shell"], input["timeout"] = json.RawMessage(`"custom"`), json.RawMessage(`"/bin/zsh"`), json.RawMessage(`"1_0"`)
	got, err = parseRawCommand(input)
	if err != nil || got.Shell != "/bin/zsh" || got.Timeout != 10 {
		t.Fatalf("got%#v %v", got, err)
	}
	input["custom_shell"] = json.RawMessage(`""`)
	got, err = parseRawCommand(input)
	if err != nil || got.Shell != "custom" {
		t.Fatal("empty custom fallback changed")
	}
	for _, timeout := range []string{`0`, `181`, `1.5`, `true`, `null`, `"abc"`, `-1`, `1844674407370955161600`} {
		input := base()
		input["timeout"] = json.RawMessage(timeout)
		if _, err := parseRawCommand(input); err == nil {
			t.Fatalf("accepted timeout%s", timeout)
		}
	}
	for _, key := range []string{"cmd", "shell", "timeout", "run_as_user"} {
		input := base()
		delete(input, key)
		if _, err := parseRawCommand(input); err == nil {
			t.Fatalf("accepted missing%s", key)
		}
	}
}
