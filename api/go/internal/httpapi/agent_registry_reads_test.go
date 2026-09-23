package httpapi

import (
	"encoding/json"
	"testing"
)

func TestRegistryVersionGuard(t *testing.T) {
	for _, v := range []string{"2.10", "2.10.0", "v2.10.0", "2.10.0+local.1", "2.10.0.post1.dev0", "2.11.0rc1", "1!1.0", "2.10.0.1"} {
		supported, valid := registryVersionSupported(v)
		if !supported || !valid {
			t.Fatal("rejected", v)
		}
	}
	for _, v := range []string{"2.9.9", "2.10.0rc1", "2.10.0.dev0", "2.10.0a1.post1", "0!2.9"} {
		supported, valid := registryVersionSupported(v)
		if supported || !valid {
			t.Fatal("incorrect old version", v)
		}
	}
	for _, v := range []string{"", "garbage", "2.10.0evil", "2..10"} {
		_, valid := registryVersionSupported(v)
		if valid {
			t.Fatal("accepted malformed", v)
		}
	}
}
func TestRegistryPagesAndProjection(t *testing.T) {
	for raw, want := range map[string]string{" +001_200 ": "1200", "-0": "0", "١٢": "12", "99999999999999999999999999": "99999999999999999999999999"} {
		got, ok := registryPage(raw)
		if !ok || got.String() != want {
			t.Fatal(raw, got, ok)
		}
	}
	for _, raw := range []string{"", "1__0", "_1", "1_", "1.0", "++1"} {
		if _, ok := registryPage(raw); ok {
			t.Fatal("accepted", raw)
		}
	}
	status, body := registryBrowseResponse(map[string]any{"path": nil, "subkeys": nil}, nil, "Computer", json.Number("1"), json.Number("200"))
	if status != 200 {
		t.Fatal(status)
	}
	data, _ := json.Marshal(body)
	if string(data) != `{"has_more":false,"page":1,"page_size":200,"path":null,"subkeys":null,"values":[]}` {
		t.Fatal(string(data))
	}
}
