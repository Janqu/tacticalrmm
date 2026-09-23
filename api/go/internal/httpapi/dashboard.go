package httpapi

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	"golang.org/x/net/websocket"
	"gorm.io/gorm"
)

func (s *Server) registerDashboard(app *fiber.App, origins []string) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/core/dashinfo/", s.authenticate, s.dashboardInfo)
	app.Get("/ws/dashinfo/", func(c fiber.Ctx) error {
		// Authenticate before handing ownership of the connection to net/http.
		token := strings.Clone(c.Query("access_token"))
		if token == "" {
			return &accounts.AuthError{Detail: "Authentication credentials were not provided."}
		}
		p, err := s.Auth.Authenticate(c.Context(), "Token "+token, "", true)
		if err != nil {
			return err
		}
		if p.User.BlockDashboardLogin || p.User.IsInstallerUser {
			return errForbidden()
		}
		handler := websocket.Server{
			Handshake: func(cfg *websocket.Config, r *http.Request) error {
				for _, origin := range origins {
					if origin != "" && r.Header.Get("Origin") == origin {
						return nil
					}
				}
				return errors.New("dashboard websocket origin is not allowed")
			},
			Handler: func(ws *websocket.Conn) { s.dashboardStream(ws, token) },
		}
		return adaptor.HTTPHandler(handler)(c)
	})
}

func (s *Server) dashboardInfo(c fiber.Ctx) error {
	p := principal(c)
	if p.User.IsInstallerUser || p.User.BlockDashboardLogin {
		return errForbidden()
	}
	db := s.DB.WithContext(c.Context())
	user, err := readRow(db, "accounts_user", p.User.ID, false)
	if err != nil {
		return err
	}
	core, err := readRow(db, "core_coresettings", 0, false)
	if err != nil {
		return err
	}
	result := map[string]any{}
	for _, key := range strings.Fields("dark_mode show_community_scripts default_agent_tbl_tab client_tree_sort client_tree_splitter loading_bar_color clear_search_when_switching date_format dash_info_color dash_positive_color dash_negative_color dash_warning_color") {
		result[key] = user[key]
	}
	result["dbl_click_action"], result["url_action"] = user["agent_dblclick_action"], user["url_action_id"]
	for _, key := range strings.Fields("ai_provider block_local_user_logon") {
		result[key] = core[key]
	}
	// These capabilities have no Go implementation yet; never advertise an
	// enabled Python-only setting to a frontend served by the pure Go API.
	result["server_scripts_enabled"] = false
	result["web_terminal_enabled"] = false
	result["sso_enabled"] = false
	result["default_date_format"] = core["date_format"]
	result["hosted"] = os.Getenv("HOSTED") == "true"
	result["trmm_version"] = productVersion
	result["latest_trmm_ver"] = productVersion // No QDT release feed configured yet.
	result["open_ai_integration_enabled"] = false
	result["run_cmd_placeholder_text"] = map[string]string{"cmd": "hostname", "powershell": "Get-ComputerInfo", "shell": "uname -a"}
	expired, err := s.dashboardCodeSignExpired(c.Context())
	if err != nil {
		return err
	}
	result["token_is_expired"] = expired
	return c.JSON(result)
}

func (s *Server) dashboardCodeSignExpired(ctx context.Context) (bool, error) {
	row, err := readRow(s.DB.WithContext(ctx), "core_codesigntoken", 0, false)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	token, _ := row["token"].(string)
	if token == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	// Use configured API hostname, never an untrusted incoming Host header.
	body, err := json.Marshal(map[string]string{"token": token, "api": s.Login.CookieDomain})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://agents.tacticalrmm.com/api/v2/checktoken", strings.NewReader(string(body)))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, nil
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusUnauthorized, nil
}

func dashboardCertDays(now time.Time) *int {
	data, err := os.ReadFile(os.Getenv("TLS_CERT_FILE"))
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	days := int(math.Floor(cert.NotAfter.Sub(now).Hours() / 24))
	return &days
}

func (s *Server) dashboardCounts(ctx context.Context, p *accounts.Principal) (map[string]any, error) {
	query := s.DB.WithContext(ctx).Table("agents_agent a").Joins("JOIN clients_site s ON s.id=a.site_id")
	if !p.User.IsSuperuser && (p.Role == nil || !p.Role.IsSuperuser) {
		if p.Role == nil {
			query = query.Where("FALSE")
		} else {
			clients := "SELECT client_id FROM accounts_role_can_view_clients WHERE role_id = ?"
			sites := "SELECT site_id FROM accounts_role_can_view_sites WHERE role_id = ?"
			query = query.Where("(NOT EXISTS ("+clients+") AND NOT EXISTS ("+sites+")) OR s.client_id IN ("+clients+") OR a.site_id IN ("+sites+")", p.Role.ID, p.Role.ID, p.Role.ID, p.Role.ID)
		}
	}
	var counts struct{ TotalServerCount, TotalWorkstationCount, TotalServerOfflineCount, TotalWorkstationOfflineCount int64 }
	err := query.Select(`COUNT(*) FILTER (WHERE a.monitoring_type='server') AS total_server_count,
 COUNT(*) FILTER (WHERE a.monitoring_type='workstation') AS total_workstation_count,
 COUNT(*) FILTER (WHERE a.monitoring_type='server' AND a.last_seen < NOW() - a.offline_time * INTERVAL '1 minute') AS total_server_offline_count,
 COUNT(*) FILTER (WHERE a.monitoring_type='workstation' AND a.last_seen < NOW() - a.offline_time * INTERVAL '1 minute') AS total_workstation_offline_count`).Scan(&counts).Error
	if err != nil {
		return nil, err
	}
	return map[string]any{"total_server_count": counts.TotalServerCount, "total_workstation_count": counts.TotalWorkstationCount, "total_server_offline_count": counts.TotalServerOfflineCount, "total_workstation_offline_count": counts.TotalWorkstationOfflineCount, "days_until_cert_expires": dashboardCertDays(time.Now())}, nil
}

func (s *Server) dashboardStream(ws *websocket.Conn, token string) {
	defer ws.Close()
	ws.MaxPayloadBytes = 4096
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			var payload []byte
			if websocket.Message.Receive(ws, &payload) != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		// Each refresh rechecks revocation, account activity and current role scope.
		// Do not retain the Fiber context: its request lifetime ends on upgrade.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		p, err := s.Auth.Authenticate(ctx, "Token "+token, "", true)
		if err != nil || p.User.BlockDashboardLogin || p.User.IsInstallerUser {
			cancel()
			return
		}
		data, err := s.dashboardCounts(ctx, p)
		cancel()
		if err != nil {
			s.Logger.Error("dashboard counts failed", "error", err)
			return
		}
		if err := ws.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return
		}
		if err := websocket.JSON.Send(ws, map[string]any{"action": "dashboard.agentcount", "data": data}); err != nil {
			return
		}
		select {
		case <-done:
			return
		case <-ticker.C:
		}
	}
}
