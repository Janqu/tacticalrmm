package httpapi

import (
	"bytes"
	"encoding/json"
	"math"
	"net/netip"
	"strconv"
	"strings"
)

// Ports of the Agent.cpu_model/graphics/local_ips/make_model/physical_disks/
// serial_number properties. Python's bare `except:` blocks map to the ok flags.

func decodeWMI(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return nil
	}
	return v
}

func wmiKey(w any, key string) (any, bool) {
	m, ok := w.(map[string]any)
	if !ok {
		return nil, false
	}
	v, ok := m[key]
	return v, ok
}

// pyFirst is `[x[key] for x in items if key in x][0]`.
func pyFirst(items any, key string) (any, bool) {
	list, ok := items.([]any)
	if !ok {
		return nil, false
	}
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			if v, has := m[key]; has {
				return v, true
			}
		}
	}
	return nil, false
}

func pyIndex0(v any) (any, bool) {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return nil, false
	}
	return list[0], true
}

func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case json.Number:
		return t.String()
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func pyTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case json.Number:
		f, err := t.Float64()
		return err != nil || f != 0
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

func pyInt(v any) (int64, bool) {
	switch t := v.(type) {
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case json.Number:
		if n, err := strconv.ParseInt(t.String(), 10, 64); err == nil {
			return n, true
		}
		f, err := t.Float64()
		return int64(f), err == nil && !math.IsInf(f, 0)
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64)
		return n, err == nil
	}
	return 0, false
}

func pyJoin(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		parts := strings.Split(t, "")
		return strings.Join(parts, ", "), true
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			s, ok := e.(string)
			if !ok {
				return "", false
			}
			parts[i] = s
		}
		return strings.Join(parts, ", "), true
	}
	return "", false
}

func groupInt(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		s = "-" + s
	}
	return s
}

func isPosix(plat string) bool { return plat == "linux" || plat == "darwin" }

func cpuModel(plat string, w any) any {
	fallback := []any{"unknown cpu model"}
	if isPosix(plat) {
		if v, ok := wmiKey(w, "cpus"); ok {
			return v
		}
		return fallback
	}
	cpus, ok := wmiKey(w, "cpu")
	list, isList := cpus.([]any)
	if !ok || !isList {
		return fallback
	}
	ret := []any{}
	for _, cpu := range list {
		if _, ok := cpu.([]any); !ok {
			return fallback
		}
		name, ok := pyFirst(cpu, "Name")
		if !ok {
			return fallback
		}
		var lp, nc any = "", ""
		if v, ok := suppressedCores(cpu); ok {
			lp, nc = v[0], v[1]
		}
		if pyTruthy(lp) && pyTruthy(nc) {
			ret = append(ret, pyStr(name)+", "+pyStr(nc)+"C/"+pyStr(lp)+"T")
		} else {
			ret = append(ret, name)
		}
	}
	return ret
}

// suppressedCores mirrors the suppress(Exception) block around lp/nc.
func suppressedCores(cpu any) ([]any, bool) {
	var lps []any
	for _, x := range cpu.([]any) {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		if _, has := m["NumberOfCores"]; has {
			v, has := m["NumberOfLogicalProcessors"]
			if !has {
				return nil, false
			}
			lps = append(lps, v)
		}
	}
	if len(lps) == 0 {
		return nil, false
	}
	nc, _ := pyFirst(cpu, "NumberOfCores") // present: lps is non-empty
	return []any{lps[0], nc}, true
}

func graphics(plat string, w any) string {
	if isPosix(plat) {
		g, ok := wmiKey(w, "gpus")
		if !ok {
			return "Error getting graphics cards"
		}
		if !pyTruthy(g) {
			return "No graphics cards"
		}
		if s, ok := pyJoin(g); ok {
			return s
		}
		return "Error getting graphics cards"
	}
	const failed = "Graphics info requires agent v1.4.14"
	g, ok := wmiKey(w, "graphics")
	list, isList := g.([]any)
	if !ok || !isList {
		return failed
	}
	ret, mrda := []string{}, 0
	for _, i := range list {
		if _, ok := i.([]any); !ok {
			return failed
		}
		caption, ok := pyFirst(i, "Caption")
		text, isStr := caption.(string)
		if !ok || !isStr {
			return failed
		}
		if strings.Contains(strings.ToLower(text), "microsoft remote display adapter") {
			mrda++
			continue
		}
		ret = append(ret, text)
	}
	if len(ret) == 0 && mrda > 0 {
		return "Microsoft Remote Display Adapter"
	}
	return strings.Join(ret, ", ")
}

func localIPs(plat string, w any) string {
	const failed = "error getting local ips"
	if isPosix(plat) {
		v, ok := wmiKey(w, "local_ips")
		if s, joined := pyJoin(v); ok && joined {
			return s
		}
		return failed
	}
	ips, ok := wmiKey(w, "network_config")
	if !ok {
		return failed
	}
	list, _ := ips.([]any)
	ret := []string{}
	for _, i := range list {
		addr, ok := pyFirst(i, "IPAddress")
		if !ok || addr == nil {
			continue
		}
		addrs, _ := addr.([]any)
		for _, ip := range addrs {
			if s, ok := ip.(string); ok {
				if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
					ret = append(ret, s)
				}
			}
		}
	}
	if len(ret) == 1 {
		return ret[0]
	}
	if len(ret) == 0 {
		return failed
	}
	return strings.Join(ret, ", ")
}

func makeModel(plat string, w any) string {
	if isPosix(plat) {
		if v, ok := wmiKey(w, "make_model"); ok {
			if s, ok := v.(string); ok {
				return s
			}
			return pyStr(v)
		}
		return "error getting make/model"
	}
	if s, ok := makeModelFull(w); ok {
		return s
	}
	if v, ok := wmiKey(w, "comp_sys_prod"); ok {
		if first, ok := pyIndex0(v); ok {
			if ver, ok := pyFirst(first, "Version"); ok {
				return pyStr(ver)
			}
		}
	}
	return "unknown make/model"
}

func makeModelFull(w any) (string, bool) {
	first := func(key string) (any, bool) {
		v, ok := wmiKey(w, key)
		if !ok {
			return nil, false
		}
		return pyIndex0(v)
	}
	compSys, ok1 := first("comp_sys")
	compSysProd, ok2 := first("comp_sys_prod")
	if !ok1 || !ok2 {
		return "", false
	}
	make, ok1 := pyFirst(compSysProd, "Vendor")
	model, ok2 := pyFirst(compSys, "Model")
	modelText, isStr := model.(string)
	if !ok1 || !ok2 || !isStr {
		return "", false
	}
	if strings.Contains(strings.ToLower(modelText), "to be filled") {
		mobo, ok := first("base_board")
		if !ok {
			return "", false
		}
		make, ok1 = pyFirst(mobo, "Manufacturer")
		model, ok2 = pyFirst(mobo, "Product")
		if !ok1 || !ok2 {
			return "", false
		}
	}
	makeText, isStr := make.(string)
	if !isStr {
		return "", false
	}
	if strings.ToLower(makeText) == "lenovo" {
		fam, ok := pyFirst(compSys, "SystemFamily")
		famText, isStr := fam.(string)
		if !ok || !isStr {
			return "", false
		}
		if !strings.Contains(strings.ToLower(famText), "to be filled") {
			model = fam
		}
	}
	return makeText + " " + pyStr(model), true
}

func physicalDisks(plat string, w any) any {
	fallback := []any{"unknown disk"}
	if isPosix(plat) {
		if v, ok := wmiKey(w, "disks"); ok {
			return v
		}
		return fallback
	}
	disks, ok := wmiKey(w, "disk")
	list, isList := disks.([]any)
	if !ok || !isList {
		return fallback
	}
	ret := []any{}
	for _, disk := range list {
		if _, ok := disk.([]any); !ok {
			return fallback
		}
		iface, ok := pyFirst(disk, "InterfaceType")
		if !ok {
			return fallback
		}
		if s, isStr := iface.(string); isStr && s == "USB" {
			continue
		}
		model, ok1 := pyFirst(disk, "Caption")
		size, ok2 := pyFirst(disk, "Size")
		n, ok3 := pyInt(size)
		if !ok1 || !ok2 || !ok3 {
			return fallback
		}
		gb := int64(math.RoundToEven(float64(n) / 1_073_741_824))
		ret = append(ret, pyStr(model)+" "+groupInt(gb)+"GB "+pyStr(iface))
	}
	return ret
}

func serialNumber(plat string, w any) any {
	if isPosix(plat) {
		if v, ok := wmiKey(w, "serialnumber"); ok {
			return v
		}
		return ""
	}
	bios, ok := wmiKey(w, "bios")
	if ok {
		if a, ok := pyIndex0(bios); ok {
			if b, ok := pyIndex0(a); ok {
				if m, ok := b.(map[string]any); ok {
					if v, ok := m["SerialNumber"]; ok {
						return v
					}
				}
			}
		}
	}
	return ""
}
