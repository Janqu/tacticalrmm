package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestAgentEnrollmentPostgres(t *testing.T) {
	if os.Getenv("TRMM_ENROLLMENT_TEST_POSTGRES") != "1" {
		t.Skip("set TRMM_ENROLLMENT_TEST_POSTGRES=1 for disposable local PostgreSQL")
	}
	db, err := gorm.Open(postgres.Open("postgresql://postgres:trmm-test-only@127.0.0.1:55439/trmm_go_test"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	defer tx.Rollback()
	schema := fmt.Sprintf("enrollment_test_%d", time.Now().UnixNano())
	sql, err := os.ReadFile("../../migrations/000_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	sqlText := strings.ReplaceAll(string(sql), "public", schema)
	if err := tx.Exec(sqlText).Error; err != nil {
		t.Fatal(err)
	}
	if err := tx.Exec("SET LOCAL search_path TO " + schema).Error; err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO clients_client (id,name,block_policy_inheritance) VALUES (1,'Local enrollment test',false)`,
		`INSERT INTO clients_site (id,name,client_id,block_policy_inheritance) VALUES (1,'Allowed',1,false),(2,'Denied',1,false)`,
	} {
		if err := tx.Exec(q).Error; err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Create(&accounts.Role{ID: 7, Name: "Scoped", CanInstallAgents: true}).Error; err != nil {
		t.Fatal(err)
	}
	if err := tx.Exec("INSERT INTO accounts_role_can_view_sites(role_id,site_id) VALUES(7,1)").Error; err != nil {
		t.Fatal(err)
	}
	s := &Server{DB: tx}
	p := &accounts.Principal{User: accounts.User{Username: "test-installer"}, Role: &accounts.Role{ID: 7, CanInstallAgents: true}}
	app := fiber.New(fiber.Config{ErrorHandler: func(c fiber.Ctx, err error) error {
		if e, ok := err.(*fiber.Error); ok {
			return c.Status(e.Code).SendString(e.Message)
		}
		return c.Status(500).SendString(err.Error())
	}})
	app.Post("/", func(c fiber.Ctx) error { c.Locals("principal", p); return c.Next() }, requireEnrollment, s.enrollAgent)
	call := func(input map[string]json.RawMessage, want int) []byte {
		t.Helper()
		body, _ := json.Marshal(input)
		req := httptest.NewRequest("POST", "/", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		got, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			t.Fatalf("want %d got %d: %s", want, res.StatusCode, got)
		}
		return got
	}
	denied := enrollmentInput()
	denied["site"] = json.RawMessage(`2`)
	call(denied, 403)
	body := call(enrollmentInput(), 200)
	var response struct {
		PK    int64  `json:"pk"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if response.PK == 0 || len(response.Token) != 40 {
		t.Fatal("missing registration credentials")
	}
	agentUser, err := accounts.AuthenticateAgentToken(t.Context(), tx, "Token "+response.Token)
	if err != nil {
		t.Fatal(err)
	}
	if agentUser.AgentID == nil || *agentUser.AgentID != response.PK {
		t.Fatal("token does not belong to new agent")
	}
	call(enrollmentInput(), 409)
	var audits int64
	tx.Table("logs_auditlog").Count(&audits)
	if audits != 1 {
		t.Fatalf("audit count: %d", audits)
	}
	var days string
	if err := tx.Raw("SELECT run_time_days::text FROM winupdate_winupdatepolicy WHERE agent_id=?", response.PK).Scan(&days).Error; err != nil {
		t.Fatal(err)
	}
	if days != "{5,6}" {
		t.Fatalf("policy days: %s", days)
	}
	if err := tx.Exec(`ALTER TABLE logs_auditlog ADD CONSTRAINT reject_enrollment CHECK (false) NOT VALID`).Error; err != nil {
		t.Fatal(err)
	}
	failed := enrollmentInput()
	failed["agent_id"] = json.RawMessage(`"ZYXWVUTSRQPONMLKJIHGFEDCBAabcdefghi"`)
	call(failed, 500)
	for _, table := range []string{"agents_agent", "accounts_user", "authtoken_token", "winupdate_winupdatepolicy"} {
		var count int64
		if err := tx.Table(table).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("partial enrollment in %s: %d", table, count)
		}
	}
}
