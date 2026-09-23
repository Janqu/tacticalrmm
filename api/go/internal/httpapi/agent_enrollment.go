package httpapi

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/amidaware/tacticalrmm/api/go/internal/pep440"
	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
)

func (s *Server) registerAgentEnrollment(app *fiber.App) {
	app.Get("/api/v3/installer/", s.authenticate, requireEnrollment, func(c fiber.Ctx) error { return c.JSON("ok") })
	app.Post("/api/v3/installer/", s.authenticate, requireEnrollment, s.installerHandshake)
	app.Post("/api/v3/newagent/", s.authenticate, requireEnrollment, s.enrollAgent)
}

func requireEnrollment(c fiber.Ctx) error {
	p := principal(c)
	if p.User.AgentID != nil || !p.Can("can_install_agents") {
		return fiber.NewError(403, forbiddenMessage)
	}
	return c.Next()
}

func (s *Server) installerHandshake(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	var version string
	if json.Unmarshal(input["version"], &version) != nil || len(version) > 255 {
		return validationError{"version": {"A valid agent version is required."}}
	}
	parsed, err := pep440.Parse(version)
	if err != nil {
		return validationError{"version": {"A valid agent version is required."}}
	}
	latest := s.LatestAgentVersion
	if latest == "" {
		latest = "2.11.0"
	}
	minimum, err := pep440.Parse(latest)
	if err != nil {
		return fiber.NewError(503, "Agent version configuration is invalid.")
	}
	if !strings.Contains(latest, "-dev") && pep440.Compare(parsed, minimum) < 0 {
		return c.Status(400).JSON(fmt.Sprintf("Old installer detected (version %s). Latest version is %s. Please generate a new installer.", version, latest))
	}
	return c.JSON("ok")
}

type agentEnrollment struct {
	AgentID        string
	Hostname       string
	Site           int64
	MonitoringType string
	Description    string
	MeshNodeID     string
	GoArch         string
	Platform       string
}

func parseAgentEnrollment(input map[string]json.RawMessage) (agentEnrollment, error) {
	var result agentEnrollment
	for _, field := range []struct {
		name     string
		target   *string
		required bool
		limit    int
	}{
		{"agent_id", &result.AgentID, true, 150}, {"hostname", &result.Hostname, true, 255},
		{"monitoring_type", &result.MonitoringType, true, 30}, {"description", &result.Description, false, 255},
		{"mesh_node_id", &result.MeshNodeID, false, 255}, {"goarch", &result.GoArch, true, 255}, {"plat", &result.Platform, true, 255},
	} {
		raw, present := input[field.name]
		if !present && !field.required {
			continue
		}
		if !present || jsonType(raw) != "str" || json.Unmarshal(raw, field.target) != nil ||
			(field.required && strings.TrimSpace(*field.target) == "") || utf8.RuneCountInString(*field.target) > field.limit || strings.ContainsRune(*field.target, 0) {
			return result, validationError{field.name: {"Invalid or missing value."}}
		}
	}
	// The ID is also a NATS subject and account name: reject subject wildcards and separators.
	if len(result.AgentID) < 21 || strings.Trim(result.AgentID, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != "" {
		return result, validationError{"agent_id": {"Use 21 to 150 ASCII letters, digits, underscores or hyphens."}}
	}
	if result.MonitoringType != "server" && result.MonitoringType != "workstation" {
		return result, validationError{"monitoring_type": {"Invalid choice."}}
	}
	switch result.Platform {
	case "windows", "linux", "darwin", "freebsd":
	default:
		return result, validationError{"plat": {"Invalid choice."}}
	}
	switch result.GoArch {
	case "amd64", "386", "arm64", "arm":
	default:
		return result, validationError{"goarch": {"Invalid choice."}}
	}
	raw := input["site"]
	if jsonType(raw) != "int" && jsonType(raw) != "str" {
		return result, validationError{"site": {"A positive site ID is required."}}
	}
	id, messages := relatedID(raw)
	if len(messages) > 0 || id <= 0 {
		return result, validationError{"site": {"A positive site ID is required."}}
	}
	result.Site = id
	return result, nil
}

func (s *Server) enrollAgent(c fiber.Ctx) error {
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	agent, err := parseAgentEnrollment(input)
	if err != nil {
		return err
	}
	var key [20]byte
	if _, err := rand.Read(key[:]); err != nil {
		return err
	}
	token := hex.EncodeToString(key[:])
	var pk int64
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		if err := hasPermOnObject(tx, c, true, agent.Site); err != nil {
			return err
		}
		if _, err := loadOrg(tx, true, agent.Site, true); err != nil {
			return err
		}
		now, actor := time.Now().UTC(), principal(c).User.Username
		if err := tx.Raw(`INSERT INTO agents_agent
   (agent_id,hostname,site_id,monitoring_type,description,mesh_node_id,goarch,plat,version,last_seen,
   overdue_email_alert,overdue_text_alert,overdue_dashboard_alert,offline_time,overdue_time,check_interval,
   needs_reboot,choco_installed,maintenance_mode,block_policy_inheritance,default_shell,default_shell_custom,
   created_by,modified_by,created_time,modified_time)
   VALUES (?,?,?,?,?,?,?,?, '0.1.0', ?, false,false,false,4,30,120,false,false,false,false,'use_global','',?,?,?,?) RETURNING id`,
			agent.AgentID, agent.Hostname, agent.Site, agent.MonitoringType, agent.Description, agent.MeshNodeID, agent.GoArch, agent.Platform, now, actor, actor, now, now).Scan(&pk).Error; err != nil {
			return err
		}
		// Unusable password: agent credentials cannot authenticate a dashboard account.
		row := map[string]any{
			"username": agent.AgentID, "password": "!", "email": "", "first_name": "", "last_name": "", "agent_id": pk,
			"is_active": true, "is_staff": false, "is_superuser": false, "is_installer_user": false, "date_joined": now,
			"created_by": actor, "modified_by": actor, "created_time": now, "modified_time": now,
			"block_dashboard_login": true, "dark_mode": true, "show_community_scripts": true, "agent_dblclick_action": "editagent",
			"default_agent_tbl_tab": "mixed", "agents_per_page": 50, "client_tree_sort": "alphafail", "client_tree_splitter": 11,
			"loading_bar_color": "red", "dash_info_color": "info", "dash_positive_color": "positive", "dash_negative_color": "negative",
			"dash_warning_color": "warning", "clear_search_when_switching": true,
		}
		if err := tx.Table("accounts_user").Create(row).Error; err != nil {
			return err
		}
		var user accounts.User
		if err := tx.Where("username = ?", agent.AgentID).First(&user).Error; err != nil {
			return err
		}
		if err := tx.Exec("INSERT INTO authtoken_token (key,user_id,created) VALUES (?,?,?)", token, user.ID, now).Error; err != nil {
			return err
		}
		policy := defaultWinUpdatePolicy()
		delete(policy, "id")
		policy["agent_id"], policy["created_time"], policy["modified_time"] = pk, now, now
		policy["created_by"], policy["modified_by"] = actor, actor
		policy["run_time_days"] = gorm.Expr("ARRAY[]::integer[]")
		if agent.MonitoringType == "workstation" {
			policy["run_time_days"] = gorm.Expr("ARRAY[5,6]::integer[]")
		}
		if err := tx.Table("winupdate_winupdatepolicy").Create(policy).Error; err != nil {
			return err
		}
		return audit.Write(tx, audit.Entry{Username: actor, Agent: &agent.Hostname, AgentID: &agent.AgentID, ObjectType: "agent", Action: "agent_install",
			Message: actor + " installed new agent " + agent.Hostname, AfterValue: map[string]any{"id": pk, "agent_id": agent.AgentID, "hostname": agent.Hostname, "site": agent.Site, "monitoring_type": agent.MonitoringType, "plat": agent.Platform}, DebugInfo: map[string]any{"ip": c.IP()}})
	})
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return c.Status(409).JSON("Agent already exists. Remove old agent first if trying to re-install.")
		}
		return err
	}
	// Enrollment does not dispatch Python jobs. Mesh provisioning and NATS credential
	// publication must be configured separately before enabling an installed agent.
	return c.JSON(fiber.Map{"pk": pk, "token": token})
}
