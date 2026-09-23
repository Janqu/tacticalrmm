package httpapi

import "testing"

func TestEffectiveTerminalShell(t *testing.T) {
	core := &terminalCore{DefaultShellWindows: "powershell", DefaultShellLinux: "custom", DefaultShellLinuxCustom: "/usr/bin/zsh"}
	for _, tc := range []struct {
		platform, shell, custom string
		core                    *terminalCore
		want                    string
	}{
		{"windows", "use_global", "", core, "powershell"},
		{"linux", "use_global", "", core, "/usr/bin/zsh"},
		{"windows", "custom", ` C:\Tools\PwSh.EXE `, core, `C:\Tools\PwSh.EXE`},
		{"windows", "custom", `\\server\tool.exe`, core, `\\server\tool.exe`},
		{"windows", "custom", `C:/tool.exe`, core, "cmd"},
		{"linux", "custom", "/bin/sh;bad", core, "bash"},
		{"darwin", "custom", "relative", core, "bash"},
		{"windows", " custom ", `C:\tool.exe`, core, "cmd"},
		{"unknown", "use_global", "", nil, "bash"},
		{"unknown", "use_global", "", core, "cmd"},
		{"windows", " POWERSHELL ", "", nil, "powershell"},
	} {
		if got := effectiveTerminalShell(tc.platform, tc.shell, tc.custom, tc.core); got != tc.want {
			t.Fatalf("%#v got%q", tc, got)
		}
	}
}

func TestTerminalVersionThreshold(t *testing.T) {
	for _, tc := range []struct {
		version string
		want    bool
	}{{"2.10.9", false}, {"2.11.0rc1", false}, {"2.11.0", true}, {"2.11.0.post1.dev1", true}, {"2.12.0dev1", true}, {"1!1.0", true}} {
		got, valid := versionAtLeast(tc.version, []int64{2, 11, 0})
		if !valid || got != tc.want {
			t.Fatalf("%s got%v valid%v", tc.version, got, valid)
		}
	}
}
