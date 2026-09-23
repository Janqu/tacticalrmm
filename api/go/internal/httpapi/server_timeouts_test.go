package httpapi

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestRawCommandTimeout(t *testing.T) {
	path := "/agents/012345678901234567890/cmd/"
	if timeoutForRequest("POST", path) != 190*time.Second {
		t.Fatal("raw command request budget is too short")
	}
	for _, item := range []struct{ method, path string }{
		{"GET", path}, {"PATCH", path}, {"POST", path + "extra/"},
		{"POST", "/agents/short/cmd/"}, {"POST", "/agents/012345678901234567890/cmd"},
	} {
		if timeoutForRequest(item.method, item.path) != 30*time.Second {
			t.Fatal("raw command timeout applied to an unsupported route")
		}
	}
}

func TestStoredScriptTimeout(t *testing.T) {
	path := "/agents/012345678901234567890/runscript/"
	if timeoutForRequest("POST", path) != 190*time.Second {
		t.Fatal("stored script request budget is too short")
	}
	for _, item := range []struct{ method, path string }{
		{"GET", path}, {"PATCH", path}, {"POST", path + "extra/"},
		{"POST", "/agents/short/runscript/"}, {"POST", "/agents/012345678901234567890/runscript"},
	} {
		if timeoutForRequest(item.method, item.path) != 30*time.Second {
			t.Fatal("stored script timeout applied to an unsupported route")
		}
	}
}

func TestServiceActionTimeoutIsBoundedToExactRoute(t *testing.T) {
	agent := "012345678901234567890"
	for _, tc := range []struct {
		method, path string
		want         time.Duration
	}{
		{"POST", "/services/" + agent + "/Spooler/", 75 * time.Second},
		{"POST", "/services/" + agent + "/My%20Service%24Name/", 75 * time.Second},
		{"POST", "/services/" + agent + "/Überwachung/", 75 * time.Second},
		{"GET", "/services/" + agent + "/Spooler/", 30 * time.Second},
		{"PUT", "/services/" + agent + "/Spooler/", 30 * time.Second},
		{"HEAD", "/services/" + agent + "/Spooler/", 30 * time.Second},
		{"POST", "/services/" + agent + "/", 30 * time.Second},
		{"POST", "/services/short/Spooler/", 30 * time.Second},
		{"POST", "/services/" + agent + "//", 30 * time.Second},
		{"POST", "/services/" + agent + "/Spooler", 30 * time.Second},
		{"POST", "/services/" + agent + "/Spooler/extra/", 30 * time.Second},
		{"POST", "/services-extra/" + agent + "/Spooler/", 30 * time.Second},
		{"POST", "/Services/" + agent + "/Spooler/", 30 * time.Second},
		{"POST", "/prefix/services/" + agent + "/Spooler/", 30 * time.Second},
		{"POST", "/services/" + agent + "/Bad%2FName/", 30 * time.Second},
		{"POST", "/services/" + agent + "/Bad%xx/", 30 * time.Second},
		{"POST", "/services/" + agent + "%2F/Spooler/", 30 * time.Second},
		{"POST", "/checks/" + agent + "/run/", 30 * time.Second},
	} {
		if got := timeoutForRequest(tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s got %s, want %s", tc.method, tc.path, got, tc.want)
		}
	}
	app := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{})
	if app.Config().WriteTimeout != 200*time.Second {
		t.Fatal("HTTP write timeout cannot support agent operation budgets")
	}
}

func TestAgentReadTimeoutIsBoundedToExactRoute(t *testing.T) {
	agent := "012345678901234567890"
	base := "/agents/" + agent
	for _, tc := range []struct {
		method, path string
		want         time.Duration
	}{
		{"GET", base + "/eventlog/Security/0/", 195 * time.Second},
		{"GET", base + "/eventlog/%53ecurity/0007/", 195 * time.Second},
		{"GET", base + "/eventlog/Security/%37/", 195 * time.Second},
		{"GET", base + "/eventlog/System/7/", 40 * time.Second},
		{"GET", base + "/eventlog/Application/7/", 40 * time.Second},
		{"GET", base + "/eventlog/security/7/", 40 * time.Second},
		{"GET", base + "/eventlog/SecurityExtra/7/", 40 * time.Second},
		{"GET", base + "/eventlog/Custom%20Log/7/", 40 * time.Second},
		{"GET", base + "/registry/", 40 * time.Second},
		{"GET", "/agents/%30" + agent[1:] + "/registry/", 40 * time.Second},
		{"HEAD", base + "/registry/", 30 * time.Second},
		{"POST", base + "/registry/", 30 * time.Second},
		{"PUT", base + "/registry/", 30 * time.Second},
		{"HEAD", base + "/eventlog/Security/7/", 30 * time.Second},
		{"POST", base + "/eventlog/Security/7/", 30 * time.Second},
		{"GET", base + "/eventlog/Security/-1/", 30 * time.Second},
		{"GET", base + "/eventlog/Security/+1/", 30 * time.Second},
		{"GET", base + "/eventlog/Security/1.0/", 30 * time.Second},
		{"GET", base + "/eventlog/Security//", 30 * time.Second},
		{"GET", base + "/eventlog/Security/7", 30 * time.Second},
		{"GET", base + "/eventlog/Security/7/extra/", 30 * time.Second},
		{"GET", base + "/eventlog//7/", 30 * time.Second},
		{"GET", base + "/eventlog/Security%2FSystem/7/", 30 * time.Second},
		{"GET", base + "/eventlog/%zz/7/", 30 * time.Second},
		{"GET", base + "/eventlog/Security/%zz/", 30 * time.Second},
		{"GET", base + "/Eventlog/Security/7/", 30 * time.Second},
		{"GET", base + "/registry", 30 * time.Second},
		{"GET", base + "/registry/create-key/", 30 * time.Second},
		{"GET", base + "/registry-extra/", 30 * time.Second},
		{"GET", base + "/Registry/", 30 * time.Second},
		{"GET", "/prefix" + base + "/registry/", 30 * time.Second},
		{"GET", "/Agents/" + agent + "/registry/", 30 * time.Second},
		{"GET", "/agents/short/registry/", 30 * time.Second},
		{"GET", "/agents/" + agent + "%2F/registry/", 30 * time.Second},
		{"GET", "/agents/" + agent + "%zz/registry/", 30 * time.Second},
	} {
		if got := timeoutForRequest(tc.method, tc.path); got != tc.want {
			t.Errorf("%s %s got %s, want %s", tc.method, tc.path, got, tc.want)
		}
	}
}

func TestRegistryMutationTimeoutIsBoundedToExactRoute(t *testing.T) {
	base := "/agents/012345678901234567890/registry/"
	for _, operation := range []string{
		"create-key", "rename-key", "create-value", "rename-value", "modify-value", "delete-key", "delete-value",
	} {
		method := "POST"
		want := 40 * time.Second
		if operation == "delete-key" || operation == "delete-value" {
			method = "DELETE"
		}
		if operation == "rename-key" {
			want = 70 * time.Second
		}
		for _, candidate := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"} {
			expected := 30 * time.Second
			if candidate == method {
				expected = want
			}
			if got := timeoutForRequest(candidate, base+operation+"/"); got != expected {
				t.Errorf("%s %s got %s, want %s", candidate, operation, got, expected)
			}
		}
		for _, path := range []string{
			base + operation,
			base + operation + "/extra/",
			base + operation + "-extra/",
			"/prefix" + base + operation + "/",
			"/agents/short/registry/" + operation + "/",
			"/agents/012345678901234567890%2F/registry/" + operation + "/",
		} {
			if got := timeoutForRequest(method, path); got != 30*time.Second {
				t.Errorf("%s %s got extended timeout %s", method, path, got)
			}
		}
	}
	for _, path := range []string{base + "Rename-key/", base + "unknown/", base + "/"} {
		if got := timeoutForRequest("POST", path); got != 30*time.Second {
			t.Errorf("unexpected extended timeout for %s: %s", path, got)
		}
	}
}
