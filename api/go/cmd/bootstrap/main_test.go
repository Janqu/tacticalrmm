package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/database"
)

func randomPassword(t *testing.T) string {
	t.Helper()
	var bytes [24]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(bytes[:])
}

func TestBootstrapValidation(t *testing.T) {
	valid := config{Username: "qdt-admin", Password: randomPassword(t)}
	if err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*config){
		func(c *config) { c.Password = "short" }, func(c *config) { c.Username = "bad user" },
		func(c *config) { c.Username = "" }, func(c *config) { c.ClientName = "orphan" },
		func(c *config) { c.ClientName = strings.Repeat("a", 256); c.SiteName = "site" },
	} {
		cfg := valid
		mutate(&cfg)
		if cfg.validate() == nil {
			t.Fatal("invalid bootstrap config accepted")
		}
	}
}

// BOOTSTRAP_TEST_DATABASE_URL points to a disposable local test database.
// Every object is isolated in a temporary schema and rolled back at the end.
func TestBootstrapFreshDatabase(t *testing.T) {
	dsn := os.Getenv("BOOTSTRAP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set BOOTSTRAP_TEST_DATABASE_URL for PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	db, err := database.Open(ctx, dsn)
	if err != nil {
		t.Fatal("test database unavailable")
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tx := db.WithContext(ctx).Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	defer tx.Rollback()
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		t.Fatal(err)
	}
	schema := "qdt_bootstrap_test_" + hex.EncodeToString(suffix[:])
	for _, file := range []string{"000_initial.sql", "001_mesh_sync.sql", "002_script_note_completion.sql"} {
		sql, err := os.ReadFile("../../migrations/" + file)
		if err != nil {
			t.Fatal(err)
		}
		body := strings.ReplaceAll(string(sql), "public.", schema+".")
		body = strings.ReplaceAll(body, "CREATE SCHEMA IF NOT EXISTS public;", "CREATE SCHEMA IF NOT EXISTS "+schema+";")
		body = strings.ReplaceAll(body, "SET search_path TO public;", "SET search_path TO "+schema+";")
		body = strings.ReplaceAll(body, "BEGIN;", "")
		body = strings.ReplaceAll(body, "COMMIT;", "")
		if err := tx.Exec(body).Error; err != nil {
			t.Fatalf("schema import %s: %v", file, err)
		}
	}
	cfg := config{Username: "qdt-admin", Password: randomPassword(t), ClientName: "Test client", SiteName: "Test site"}
	created, err := bootstrap(ctx, tx, cfg)
	if err != nil || !created {
		t.Fatalf("fresh bootstrap: created=%v err=%v", created, err)
	}
	var user accounts.User
	if err := tx.Where("username = ?", cfg.Username).First(&user).Error; err != nil {
		t.Fatal(err)
	}
	if !user.IsActive || !user.IsSuperuser || user.BlockDashboardLogin || user.RoleID == nil {
		t.Fatal("root is not login-ready")
	}
	if valid, _ := accounts.VerifyPassword(cfg.Password, user.Password); !valid {
		t.Fatal("root password does not verify")
	}
	original := user.Password
	cfg.Password = randomPassword(t)
	created, err = bootstrap(ctx, tx, cfg)
	if err != nil || created {
		t.Fatalf("repeat bootstrap: created=%v err=%v", created, err)
	}
	if err := tx.First(&user, user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if user.Password != original {
		t.Fatal("bootstrap reset the existing password")
	}
	for _, table := range []string{"accounts_user", "accounts_role", "core_coresettings", "clients_client", "clients_site"} {
		var count int64
		if err := tx.Table(table).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("%s count=%d", table, count)
		}
	}
	var core struct {
		SMTPHostPassword                                                                                                 string
		BlockLocalUserLogon, SSOEnabled, AgentAutoUpdate, SyncMeshWithTrmm, EnableServerScripts, EnableServerWebterminal bool
	}
	if err := tx.Table("core_coresettings").First(&core).Error; err != nil {
		t.Fatal(err)
	}
	if core.SMTPHostPassword != "" || core.BlockLocalUserLogon || core.SSOEnabled || core.AgentAutoUpdate || core.SyncMeshWithTrmm || core.EnableServerScripts || core.EnableServerWebterminal {
		t.Fatal("fresh integration side effects must be disabled")
	}
	cfg.Username = "another-root"
	if _, err := bootstrap(ctx, tx, cfg); err == nil {
		t.Fatal("must not add another root to an existing installation")
	}
}

func TestInitialSchemaHasNoSeedData(t *testing.T) {
	data, err := os.ReadFile("../../migrations/000_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	sql := string(data)
	for _, forbidden := range []string{"COPY ", "INSERT INTO ", "pg_catalog.setval(", "pbkdf2_sha256$", "go_mesh_sync", "go_script_note_completion"} {
		if strings.Contains(sql, forbidden) {
			t.Fatalf("initial schema contains forbidden seed/extension marker %q", forbidden)
		}
	}
	if strings.Count(sql, "CREATE TABLE public.") != 83 {
		t.Fatal("initial model schema table count changed; review snapshot")
	}
}
