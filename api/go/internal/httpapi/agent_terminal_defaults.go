package httpapi

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerTerminalDefaults(app *fiber.App) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/agents/:agent_id/terminal-defaults/", s.authenticate, require("can_use_terminal"), s.agentTerminalDefaults)
}

func (s *Server) agentTerminalDefaults(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	if err := s.hasPermOnAgent(c, id); err != nil {
		return err
	}
	var agent struct{ AgentID, Hostname, Plat, DefaultShell, DefaultShellCustom, Version string }
	query := s.DB.WithContext(c.Context()).Table("agents_agent a").Joins("JOIN clients_site s ON s.id=a.site_id")
	err = agentScope(query, c).Select("a.agent_id,a.hostname,a.plat,a.default_shell,a.default_shell_custom,a.version").Where("a.agent_id = ?", id).Take(&agent).Error
	if err != nil {
		return lookupError(err, "Agent")
	}
	supported, valid := versionAtLeast(agent.Version, []int64{2, 11, 0})
	if !valid {
		return fmt.Errorf("invalid agent terminal version")
	}
	var core terminalCore
	err = s.DB.WithContext(c.Context()).Table("core_coresettings").Select("id,terminal_mode,default_shell_windows,default_shell_windows_custom,default_shell_linux,default_shell_linux_custom,default_shell_darwin,default_shell_darwin_custom").Order("id").Take(&core).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	var defaults *terminalCore
	mode := "new"
	if err == nil {
		defaults, mode = &core, core.TerminalMode
	}
	effective := effectiveTerminalShell(agent.Plat, agent.DefaultShell, agent.DefaultShellCustom, defaults)
	resolved := strings.ToLower(strings.TrimSpace(effective))
	if resolved != "cmd" && resolved != "powershell" && resolved != "bash" {
		resolved = "custom"
	}
	return c.JSON(fiber.Map{"agent_id": agent.AgentID, "hostname": agent.Hostname, "plat": agent.Plat, "default_shell": agent.DefaultShell,
		"resolved_default_shell": resolved, "effective_default_shell": effective, "terminal_mode": mode, "supports_new_terminal": supported})
}

type terminalCore struct {
	ID                                             int64
	TerminalMode                                   string
	DefaultShellWindows, DefaultShellWindowsCustom string
	DefaultShellLinux, DefaultShellLinuxCustom     string
	DefaultShellDarwin, DefaultShellDarwinCustom   string
}

func effectiveTerminalShell(platform, shell, custom string, core *terminalCore) string {
	if shell == "" || shell == "use_global" {
		if core == nil {
			if platform == "windows" {
				return "cmd"
			}
			return "bash"
		}
		switch platform {
		case "windows":
			shell, custom = core.DefaultShellWindows, core.DefaultShellWindowsCustom
		case "linux":
			shell, custom = core.DefaultShellLinux, core.DefaultShellLinuxCustom
		case "darwin":
			shell, custom = core.DefaultShellDarwin, core.DefaultShellDarwinCustom
		default:
			return "cmd"
		}
	}
	fallback := "cmd"
	if platform == "linux" || platform == "darwin" {
		fallback = "bash"
	}
	if shell == "custom" {
		value := strings.TrimSpace(custom)
		if terminalPathValid(platform, value) {
			return value
		}
		return fallback
	}
	token := strings.ToLower(strings.TrimSpace(shell))
	if platform == "windows" && (token == "cmd" || token == "powershell") {
		return token
	}
	if (platform == "linux" || platform == "darwin") && token == "bash" {
		return token
	}
	return fallback
}

func terminalPathValid(platform, value string) bool {
	if value == "" || strings.ContainsAny(value, "\"'\n\r&|;") {
		return false
	}
	if platform == "linux" || platform == "darwin" {
		return strings.HasPrefix(value, "/")
	}
	if platform != "windows" || !strings.HasSuffix(strings.ToLower(value), ".exe") {
		return false
	}
	unc := strings.HasPrefix(value, `\\`)
	drive := len(value) >= 3 && ((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= 'A' && value[0] <= 'Z')) && value[1:3] == `:\`
	return unc || drive
}
