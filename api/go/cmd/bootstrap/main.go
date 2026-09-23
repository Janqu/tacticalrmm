// bootstrap creates the first qdt-rmm account in a fresh SQL-initialized database.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/database"
	"gorm.io/gorm"
)

type config struct {
	Username, Password, ClientName, SiteName string
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := database.Open(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap failed: verify DATABASE_URL and database availability")
		os.Exit(1)
	}
	pool, err := db.DB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap failed: database pool unavailable")
		os.Exit(1)
	}
	defer pool.Close()
	created, err := bootstrap(ctx, db, cfg)
	if err != nil {
		// Database errors can contain SQL parameters, including a password hash.
		fmt.Fprintln(os.Stderr, "bootstrap failed: expected a fresh migrated database or the existing configured active root account; no credentials changed")
		os.Exit(1)
	}
	if created {
		fmt.Println("qdt-rmm root account created; password was not logged")
	} else {
		fmt.Println("qdt-rmm already bootstrapped; existing credentials preserved")
	}
}

func loadConfig() (config, error) {
	cfg := config{Username: os.Getenv("ROOT_USER"), Password: os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"), ClientName: os.Getenv("BOOTSTRAP_CLIENT_NAME"), SiteName: os.Getenv("BOOTSTRAP_SITE_NAME")}
	if file := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD_FILE"); file != "" {
		if cfg.Password != "" {
			return config{}, errors.New("set only BOOTSTRAP_ADMIN_PASSWORD or BOOTSTRAP_ADMIN_PASSWORD_FILE")
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return config{}, errors.New("cannot read BOOTSTRAP_ADMIN_PASSWORD_FILE")
		}
		cfg.Password = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	}
	if os.Getenv("DATABASE_URL") == "" {
		return config{}, errors.New("DATABASE_URL is required")
	}
	if err := cfg.validate(); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func (c config) validate() error {
	if c.Username == "" || utf8.RuneCountInString(c.Username) > 150 {
		return errors.New("ROOT_USER must contain 1–150 username characters")
	}
	for _, r := range c.Username {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("@.+-_", r) {
			return errors.New("ROOT_USER contains invalid username characters")
		}
	}
	if utf8.RuneCountInString(c.Password) < 16 || len(c.Password) > 1024 || strings.ContainsRune(c.Password, 0) {
		return errors.New("bootstrap password must contain at least 16 characters, at most 1024 bytes and no NUL")
	}
	if (c.ClientName == "") != (c.SiteName == "") {
		return errors.New("set BOOTSTRAP_CLIENT_NAME and BOOTSTRAP_SITE_NAME together, or neither")
	}
	for _, name := range []string{c.ClientName, c.SiteName} {
		if utf8.RuneCountInString(name) > 255 || strings.ContainsRune(name, 0) {
			return errors.New("bootstrap client and site names must fit 255 characters and contain no NUL")
		}
	}
	return nil
}

func bootstrap(ctx context.Context, db *gorm.DB, cfg config) (bool, error) {
	if err := cfg.validate(); err != nil {
		return false, err
	}
	created := false
	err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// Serialize concurrent one-shot bootstrap containers without affecting API users.
		if err := tx.Exec("SELECT pg_advisory_xact_lock(716482001)").Error; err != nil {
			return err
		}
		var users int64
		if err := tx.Model(&accounts.User{}).Count(&users).Error; err != nil {
			return err
		}
		if users > 0 {
			var root accounts.User
			if err := tx.Where("username = ?", cfg.Username).First(&root).Error; err != nil {
				return err
			}
			var coreCount int64
			if err := tx.Table("core_coresettings").Count(&coreCount).Error; err != nil {
				return err
			}
			if !root.IsSuperuser || !root.IsActive || root.IsInstallerUser || coreCount != 1 {
				return errors.New("existing installation is not a completed bootstrap")
			}
			return nil
		}
		for _, table := range []string{"accounts_role", "core_coresettings", "clients_client", "clients_site", "agents_agent"} {
			var count int64
			if err := tx.Table(table).Count(&count).Error; err != nil {
				return err
			}
			if count != 0 {
				return errors.New("bootstrap requires an empty database")
			}
		}
		now := time.Now().UTC()
		role := accounts.Role{Name: "qdt-rmm Administrators", IsSuperuser: true, CreatedBy: &cfg.Username, ModifiedBy: &cfg.Username, CreatedTime: &now, ModifiedTime: &now}
		if err := tx.Create(&role).Error; err != nil {
			return err
		}
		hash, err := accounts.PasswordHash(&cfg.Password)
		if err != nil {
			return err
		}
		user := map[string]any{
			"username": cfg.Username, "password": hash, "email": "", "first_name": "", "last_name": "",
			"is_active": true, "is_superuser": true, "is_staff": true, "role_id": role.ID, "date_joined": now,
			"created_by": cfg.Username, "modified_by": cfg.Username, "created_time": now, "modified_time": now,
			"block_dashboard_login": false, "totp_key": "", "dark_mode": true, "show_community_scripts": true,
			"agent_dblclick_action": "editagent", "default_agent_tbl_tab": "mixed", "agents_per_page": 50,
			"client_tree_sort": "alphafail", "client_tree_splitter": 11, "loading_bar_color": "red",
			"dash_info_color": "info", "dash_positive_color": "positive", "dash_negative_color": "negative", "dash_warning_color": "warning",
			"clear_search_when_switching": true, "is_installer_user": false,
		}
		if err := tx.Table("accounts_user").Create(user).Error; err != nil {
			return err
		}
		core := map[string]any{
			"created_by": cfg.Username, "modified_by": cfg.Username, "created_time": now, "modified_time": now,
			"email_alert_recipients": gorm.Expr("ARRAY[]::varchar[]"), "sms_alert_recipients": gorm.Expr("ARRAY[]::varchar[]"),
			"smtp_from_email": "", "smtp_host": "", "smtp_host_user": "", "smtp_host_password": "", "smtp_port": 587, "smtp_requires_auth": true,
			"default_time_zone": "UTC", "check_history_prune_days": 30, "resolved_alerts_prune_days": 0, "agent_history_prune_days": 60,
			"debug_log_prune_days": 30, "audit_log_prune_days": 0, "report_history_prune_days": 0, "agent_debug_level": "info", "clear_faults_days": 0,
			"mesh_token": "", "mesh_username": "", "mesh_site": "", "mesh_device_group": "qdt-rmm", "sync_mesh_with_trmm": false, "agent_auto_update": false,
			"date_format": "MMM-DD-YYYY - HH:mm", "open_ai_model": "gpt-3.5-turbo", "ai_provider": "openai", "minimax_model": "MiniMax-M3",
			"enable_server_scripts": false, "enable_server_webterminal": false, "ai_chat_enabled": false, "notify_on_info_alerts": false, "notify_on_warning_alerts": true,
			"block_local_user_logon": false, "sso_enabled": false, "default_shell_windows": "cmd", "default_shell_windows_custom": "",
			"default_shell_linux": "bash", "default_shell_linux_custom": "", "default_shell_darwin": "bash", "default_shell_darwin_custom": "", "terminal_mode": "new",
		}
		if err := tx.Table("core_coresettings").Create(core).Error; err != nil {
			return err
		}
		if cfg.ClientName != "" {
			client := map[string]any{"name": cfg.ClientName, "block_policy_inheritance": false, "failing_checks": gorm.Expr("'{}'::jsonb"), "created_by": cfg.Username, "modified_by": cfg.Username, "created_time": now, "modified_time": now}
			if err := tx.Table("clients_client").Create(client).Error; err != nil {
				return err
			}
			var clientID int64
			if err := tx.Table("clients_client").Where("name = ?", cfg.ClientName).Pluck("id", &clientID).Error; err != nil {
				return err
			}
			site := map[string]any{"name": cfg.SiteName, "client_id": clientID, "block_policy_inheritance": false, "failing_checks": gorm.Expr("'{}'::jsonb"), "created_by": cfg.Username, "modified_by": cfg.Username, "created_time": now, "modified_time": now}
			if err := tx.Table("clients_site").Create(site).Error; err != nil {
				return err
			}
		}
		created = true
		return nil
	})
	return created, err
}
