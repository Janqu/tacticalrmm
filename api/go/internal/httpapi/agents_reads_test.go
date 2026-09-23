package httpapi

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"reflect"
	"testing"
)

func wmiFixture(t *testing.T, raw string) any {
	t.Helper()
	return decodeWMI(json.RawMessage(raw))
}

func TestWindowsWMIProperties(t *testing.T) {
	w := wmiFixture(t, `{
		"cpu": [[{"Name": "Xeon"}, {"NumberOfCores": 4, "NumberOfLogicalProcessors": 8}]],
		"graphics": [[{"Caption": "Microsoft Remote Display Adapter"}], [{"Caption": "NVIDIA"}]],
		"network_config": [[{"IPAddress": ["10.0.0.5", "fe80::1"]}], [{"IPAddress": ["192.168.1.2"]}], [{"Other": 1}]],
		"comp_sys": [[{"Model": "To be filled by O.E.M."}, {"SystemFamily": "ThinkPad"}]],
		"comp_sys_prod": [[{"Vendor": "LENOVO"}]],
		"base_board": [[{"Manufacturer": "Lenovo"}, {"Product": "20XW"}]],
		"disk": [[{"InterfaceType": "SCSI"}, {"Caption": "Disk A"}, {"Size": "1000204886016"}],
		         [{"InterfaceType": "USB"}, {"Caption": "Stick"}, {"Size": 1}]],
		"bios": [[{"SerialNumber": "SN1"}]]
	}`)
	if got := cpuModel("windows", w); !reflect.DeepEqual(got, []any{"Xeon, 4C/8T"}) {
		t.Fatal(got)
	}
	if got := graphics("windows", w); got != "NVIDIA" {
		t.Fatal(got)
	}
	if got := localIPs("windows", w); got != "10.0.0.5, 192.168.1.2" {
		t.Fatal(got)
	}
	if got := makeModel("windows", w); got != "Lenovo ThinkPad" {
		t.Fatal(got)
	}
	if got := physicalDisks("windows", w); !reflect.DeepEqual(got, []any{"Disk A 932GB SCSI"}) {
		t.Fatal(got)
	}
	if got := serialNumber("windows", w); got != "SN1" {
		t.Fatal(got)
	}
}

func TestWMIFallbacks(t *testing.T) {
	for _, w := range []any{nil, wmiFixture(t, `[]`), wmiFixture(t, `{}`)} {
		if !reflect.DeepEqual(cpuModel("windows", w), []any{"unknown cpu model"}) ||
			graphics("windows", w) != "Graphics info requires agent v1.4.14" ||
			localIPs("windows", w) != "error getting local ips" ||
			makeModel("windows", w) != "unknown make/model" ||
			!reflect.DeepEqual(physicalDisks("windows", w), []any{"unknown disk"}) ||
			serialNumber("windows", w) != "" ||
			graphics("linux", w) != "Error getting graphics cards" ||
			makeModel("linux", w) != "error getting make/model" {
			t.Fatalf("unexpected fallback for %v", w)
		}
	}
	lin := wmiFixture(t, `{"gpus": [], "local_ips": ["a", "b"], "serialnumber": "S"}`)
	if graphics("linux", lin) != "No graphics cards" || localIPs("darwin", lin) != "a, b" || serialNumber("linux", lin) != "S" {
		t.Fatal("posix properties")
	}
}

func TestUnpickleFlatDict(t *testing.T) {
	// pickle.dumps({"total": 3, "has_failing_checks": True}, protocol=5)
	data := []byte("\x80\x05\x95\x2a\x00\x00\x00\x00\x00\x00\x00}\x94(\x8c\x05total\x94K\x03\x8c\x12has_failing_checks\x94\x88u.")
	got, err := unpickleFlatDict(data)
	if err != nil || got["total"] != int64(3) || got["has_failing_checks"] != true {
		t.Fatal(got, err)
	}
	// GLOBAL / REDUCE (code execution) must be rejected.
	if _, err := unpickleFlatDict([]byte("cos\nsystem\n(S'id'\ntR.")); err == nil {
		t.Fatal("accepted a non-dict pickle")
	}
}

func TestAgentRoutesRequireAuthentication(t *testing.T) {
	app := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{})
	for _, path := range []string{"/agents/", "/agents/history/", "/agents/v2/history/", "/agents/notes/", "/agents/notes/1/",
		"/agents/0123456789012345678901/history/", "/agents/v2/0123456789012345678901/history/", "/agents/0123456789012345678901/notes/"} {
		for _, method := range []string{"GET", "HEAD"} {
			response, err := app.Test(httptest.NewRequest(method, path, nil))
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != 401 {
				t.Errorf("%s %s returned %d", method, path, response.StatusCode)
			}
		}
	}
}

func TestAgentNoteWritesRequireAuthentication(t *testing.T) {
	app := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{})
	for _, route := range []struct{ method, path string }{
		{"POST", "/agents/notes/"}, {"PUT", "/agents/notes/1/"}, {"DELETE", "/agents/notes/1/"},
	} {
		response, err := app.Test(httptest.NewRequest(route.method, route.path, nil))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 401 {
			t.Errorf("%s %s returned %d", route.method, route.path, response.StatusCode)
		}
	}
}
