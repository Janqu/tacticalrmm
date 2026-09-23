package httpapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

const productVersion = "0.1.0-dev"

type Server struct {
	DB                     *gorm.DB
	Logger                 *slog.Logger
	Auth                   accounts.Authenticator
	TOTPIssuer             string
	Login                  LoginConfig
	RootUser               string
	Cache                  *redis.Client // Django cache (db 10); agent check summaries
	NATS                   *agentbus.Client
	LatestAgentVersion     string
	NushellEnableConfig    bool
	DenoDefaultPermissions string
}

type Config struct {
	Origins                []string
	Login                  LoginConfig
	RootUser               string
	Cache                  *redis.Client
	NATS                   *agentbus.Client
	LatestAgentVersion     string
	NushellEnableConfig    bool
	DenoDefaultPermissions *string
}

func New(db *gorm.DB, logger *slog.Logger, config Config) *fiber.App {
	s := &Server{DB: db, Logger: logger, Auth: accounts.Authenticator{DB: db}, Login: config.Login, RootUser: config.RootUser, Cache: config.Cache, NATS: config.NATS}
	s.LatestAgentVersion = config.LatestAgentVersion
	s.NushellEnableConfig = config.NushellEnableConfig
	s.DenoDefaultPermissions = "--allow-all"
	if config.DenoDefaultPermissions != nil {
		s.DenoDefaultPermissions = *config.DenoDefaultPermissions
	}
	if s.LatestAgentVersion == "" {
		s.LatestAgentVersion = "2.11.0"
	}
	origins := config.Origins
	if len(origins) > 0 {
		if origin, err := url.Parse(origins[0]); err == nil {
			s.TOTPIssuer = origin.Host
		}
	}
	app := fiber.New(fiber.Config{
		AppName:       "QDT RMM Go API",
		StrictRouting: true,
		CaseSensitive: true,
		BodyLimit:     4 * 1024 * 1024,
		ReadTimeout:   30 * time.Second,
		WriteTimeout:  200 * time.Second,
		IdleTimeout:   60 * time.Second,
		ErrorHandler:  s.handleError,
	})
	app.Use(requestid.New(), recover.New())
	if len(origins) > 0 {
		app.Use(cors.New(cors.Config{
			AllowOrigins:     origins,
			AllowCredentials: true,
			AllowHeaders:     []string{"Authorization", "Content-Type", "X-API-KEY", "X-CSRFToken"},
			AllowMethods:     []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		}))
	}
	app.Use(func(c fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(c.Context(), timeoutForRequest(c.Method(), c.Path()))
		defer cancel()
		c.SetContext(ctx)
		return c.Next()
	})
	app.Get("/", s.optionalAuth, func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
	app.Get("/core/version/", s.authenticate, func(c fiber.Ctx) error {
		return c.JSON(productVersion)
	})
	app.Post("/logout/", s.tokenAuthentication, s.logout)
	app.Post("/v2/checkcreds/", s.optionalAuth, s.loginThrottle, s.login)
	app.Post("/v2/login/", s.optionalAuth, s.loginThrottle, s.login)
	app.Post("/logoutall/", s.tokenAuthentication, s.logoutAll)
	app.Get("/_allauth/browser/v1/config/", s.allauthConfig)
	s.registerDashboard(app, config.Origins)
	s.registerSNMPReads(app)
	s.registerAgentInstaller(app)
	s.registerAgentEnrollment(app)
	s.registerInventoryReads(app)
	s.registerAlertChannelOptions(app)
	s.registerReportReads(app)
	s.registerServerMaintenance(app)
	readMethods := []string{fiber.MethodGet, fiber.MethodHead}
	for _, path := range []string{"/clients/", "/clients/:pk<regex(^[0-9]+$)>/"} {
		app.Add(readMethods, path, s.authenticate, requireRead("can_list_clients", "can_manage_clients"), s.readClients)
	}
	for _, path := range []string{"/clients/sites/", "/clients/sites/:pk<regex(^[0-9]+$)>/"} {
		app.Add(readMethods, path, s.authenticate, requireRead("can_list_sites", "can_manage_sites"), s.readSites)
	}
	app.Post("/accounts/users/", s.authenticate, require("can_manage_accounts"), s.addAccount)
	app.Add(readMethods, "/accounts/users/", s.authenticate, requireRead("can_list_accounts", "can_manage_accounts"), s.users)
	app.Put("/accounts/:pk<regex(^[0-9]+$)>/users/", s.authenticate, require("can_manage_accounts"), s.updateAccount)
	app.Delete("/accounts/:pk<regex(^[0-9]+$)>/users/", s.authenticate, require("can_manage_accounts"), s.deleteUser)
	app.Add(readMethods, "/accounts/:pk<regex(^[0-9]+$)>/users/", s.authenticate, requireRead("can_list_accounts", "can_manage_accounts"), s.user)
	app.Add(readMethods, "/accounts/users/:pk<regex(^[0-9]+$)>/sessions/", s.authenticate, requireRead("can_list_accounts", "can_manage_accounts"), s.sessions)
	app.Delete("/accounts/users/:pk<regex(^[0-9]+$)>/sessions/", s.authenticate, require("can_manage_accounts"), s.deleteSessions)
	app.Delete("/accounts/sessions/:digest/", s.authenticate, require("can_manage_accounts"), s.deleteSession)
	app.Add(readMethods, "/accounts/roles/", s.authenticate, requireRead("can_list_roles", "can_manage_roles"), s.roles)
	app.Post("/accounts/roles/", s.authenticate, require("can_manage_roles"), s.addRole)
	app.Add(readMethods, "/accounts/roles/:pk<regex(^[0-9]+$)>/", s.authenticate, requireRead("can_list_roles", "can_manage_roles"), s.role)
	app.Add([]string{fiber.MethodPut, fiber.MethodDelete}, "/accounts/roles/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_manage_roles"), s.mutateRole)
	app.Add(readMethods, "/accounts/apikeys/", s.authenticate, requireRead("can_list_api_keys", "can_manage_api_keys"), s.apiKeys)
	app.Post("/accounts/apikeys/", s.authenticate, require("can_manage_api_keys"), s.addAPIKey)
	app.Put("/accounts/apikeys/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_manage_api_keys"), s.updateAPIKey)
	app.Delete("/accounts/apikeys/:pk<regex(^[0-9]+$)>/", s.authenticate, require("can_manage_api_keys"), s.deleteAPIKey)
	app.Patch("/accounts/users/ui/", s.authenticate, s.userUI)
	app.Put("/accounts/resetpw/", s.authenticate, s.localAccount, s.resetPassword)
	app.Put("/accounts/reset2fa/", s.authenticate, s.localAccount, s.resetTwoFactor)
	app.Post("/accounts/users/setup_totp/", s.authenticate, s.setupTOTP)
	for _, path := range []string{"/accounts/users/reset/", "/accounts/users/reset_totp/"} {
		app.Add([]string{fiber.MethodPost, fiber.MethodPut}, path, s.authenticate, s.userAction)
	}
	s.coreRoutes(app)
	s.registerAgentReads(app)
	s.registerAgentVersions(app)
	s.registerTerminalDefaults(app)
	s.registerScriptHistory(app)
	s.registerAgentCommands(app)
	s.registerAgentCallbacks(app)
	s.registerRawCommands(app)
	s.registerScriptExecution(app)
	s.registerHistoryCallbacks(app)
	s.registerEventLogReads(app)
	s.registerRegistryReads(app)
	s.registerRegistryWrites(app)
	s.registerScheduledReboot(app)
	s.registerAgentProcesses(app)
	s.registerServiceReads(app)
	s.registerServiceWrites(app)
	s.registerScriptReads(app)
	s.registerScriptSnippetRoutes(app)
	s.registerScriptWrites(app)
	s.registerAutomationReads(app)
	s.registerPatchPolicyWrites(app)
	s.registerPatchPolicyReset(app)
	s.registerAlertReads(app)
	s.registerAlertWrites(app)
	s.registerCheckReads(app)
	s.registerAgentCheckReads(app)
	s.registerAutoTaskReads(app)
	s.registerAgentTaskReads(app)
	s.registerAlertQueries(app)
	s.registerLogReads(app)
	s.registerSoftwareReads(app)
	s.registerSoftwareWrites(app)
	s.registerWinUpdates(app)
	s.registerWinUpdateCommands(app)
	s.registerWinUpdateCallbacks(app)
	s.registerPendingActions(app)
	s.registerClientSiteWrites(app)
	app.Use(func(c fiber.Ctx) error { return fiber.NewError(404, "Not found.") })
	return app
}

func (s *Server) authenticate(c fiber.Ctx) error        { return s.authenticateWith(c, false) }
func (s *Server) tokenAuthentication(c fiber.Ctx) error { return s.authenticateWith(c, true) }

func (s *Server) optionalAuth(c fiber.Ctx) error {
	parts := strings.Fields(c.Get("Authorization"))
	if c.Get("X-API-KEY") == "" && (len(parts) == 0 || !strings.EqualFold(parts[0], "Token")) {
		return c.Next()
	}
	return s.authenticate(c)
}

func (s *Server) authenticateWith(c fiber.Ctx, tokenOnly bool) error {
	p, err := s.Auth.Authenticate(c.Context(), c.Get("Authorization"), c.Get("X-API-KEY"), tokenOnly)
	if err != nil {
		return err
	}
	c.Locals("principal", p)
	return c.Next()
}

// Agent operations have different bounded reply times. Extend only exact routes,
// leaving every other request under the default deadline.
func timeoutForRequest(method, path string) time.Duration {
	if method != fiber.MethodPost && method != fiber.MethodGet && method != fiber.MethodDelete {
		return 30 * time.Second
	}
	parts := strings.Split(path, "/")
	if (len(parts) < 5 || len(parts) > 7) || parts[0] != "" || parts[len(parts)-1] != "" {
		return 30 * time.Second
	}
	agent, err := url.PathUnescape(parts[2])
	if err != nil || utf8.RuneCountInString(agent) < 21 || strings.Contains(agent, "/") {
		return 30 * time.Second
	}
	if method == fiber.MethodPost && len(parts) == 5 && parts[1] == "services" {
		service, err := url.PathUnescape(parts[3])
		if err == nil && service != "" && !strings.Contains(service, "/") {
			return 75 * time.Second
		}
	}
	if method == fiber.MethodPost && len(parts) == 5 && parts[1] == "agents" && (parts[3] == "cmd" || parts[3] == "runscript") {
		return 190 * time.Second
	}
	if len(parts) == 6 && parts[1] == "agents" && parts[3] == "registry" {
		if method == fiber.MethodPost {
			switch parts[4] {
			case "rename-key":
				return 70 * time.Second
			case "create-key", "create-value", "rename-value", "modify-value":
				return 40 * time.Second
			}
		}
		if method == fiber.MethodDelete && (parts[4] == "delete-key" || parts[4] == "delete-value") {
			return 40 * time.Second
		}
	}
	if method == fiber.MethodGet && parts[1] == "agents" {
		if len(parts) == 5 && parts[3] == "registry" {
			return 40 * time.Second
		}
		if len(parts) == 7 && parts[3] == "eventlog" {
			logtype, logErr := url.PathUnescape(parts[4])
			days, daysErr := url.PathUnescape(parts[5])
			if logErr == nil && logtype != "" && !strings.Contains(logtype, "/") &&
				daysErr == nil && days != "" && strings.Trim(days, "0123456789") == "" {
				if logtype == "Security" {
					return 195 * time.Second
				}
				return 40 * time.Second
			}
		}
	}
	return 30 * time.Second
}

func principal(c fiber.Ctx) *accounts.Principal { return c.Locals("principal").(*accounts.Principal) }

func require(permission string) fiber.Handler {
	return func(c fiber.Ctx) error {
		if !principal(c).Can(permission) {
			return fiber.NewError(403, "You do not have permission to perform this action.")
		}
		return c.Next()
	}
}

// Django's AccountsPerms and RolesPerms treat HEAD as a management request.
func requireRead(read, write string) fiber.Handler {
	return func(c fiber.Ctx) error {
		permission := read
		if c.Method() == fiber.MethodHead {
			permission = write
		}
		return require(permission)(c)
	}
}

func identifier(c fiber.Ctx) (int64, error) {
	raw := c.Params("pk")
	if raw == "" || strings.Trim(raw, "0123456789") != "" {
		return 0, fiber.NewError(404, "Not found.")
	}
	raw = strings.TrimLeft(raw, "0")
	if raw == "" {
		raw = "0"
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id < 0 {
		return 0, fiber.NewError(404, "Not found.")
	}
	return id, nil
}

func (s *Server) handleError(c fiber.Ctx, err error) error {
	var auth *accounts.AuthError
	var httpError *fiber.Error
	var validation validationError
	switch {
	case errors.As(err, &validation):
		return c.Status(400).JSON(validation)
	case errors.As(err, &auth):
		c.Set("WWW-Authenticate", "Token")
		return c.Status(401).JSON(fiber.Map{"detail": auth.Detail})
	case errors.Is(err, gorm.ErrRecordNotFound):
		return c.Status(404).JSON(fiber.Map{"detail": "Not found."})
	case errors.As(err, &httpError):
		return c.Status(httpError.Code).JSON(fiber.Map{"detail": httpError.Message})
	default:
		// Never log SQL errors verbatim: they can include keys or passwords.
		s.Logger.Error("request failed", "request_id", requestid.FromContext(c), "error_type", fmt.Sprintf("%T", err))
		return c.Status(500).JSON(fiber.Map{"detail": "Internal server error."})
	}
}

func lookupError(err error, model string) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return fiber.NewError(404, "No "+model+" matches the given query.")
	}
	return err
}

// DRF preserves all six microsecond digits, unlike time.Time's RFC3339Nano JSON.
func datetime(t *time.Time) *string {
	if t == nil {
		return nil
	}
	format := "2006-01-02T15:04:05Z07:00"
	if t.Nanosecond() != 0 {
		format = "2006-01-02T15:04:05.000000Z07:00"
	}
	value := t.UTC().Format(format)
	return &value
}
