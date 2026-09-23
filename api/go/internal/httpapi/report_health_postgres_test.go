package httpapi

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Opt-in only; the address and database are deliberately fixed to the local
// disposable test container. All fixtures live in a transaction-local schema.
func TestHealthReportPostgres(t *testing.T) {
	if os.Getenv("TRMM_REPORT_TEST_POSTGRES") != "1" {
		t.Skip("set TRMM_REPORT_TEST_POSTGRES=1 for local test container")
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
	schema := fmt.Sprintf("health_report_test_%d", time.Now().UnixNano())
	for _, statement := range []string{
		"CREATE SCHEMA " + schema, "SET LOCAL search_path TO " + schema,
		`CREATE TABLE clients_client (id bigint PRIMARY KEY,name text,server_policy_id bigint,workstation_policy_id bigint,block_policy_inheritance bool DEFAULT false)`,
		`CREATE TABLE clients_site (id bigint PRIMARY KEY,name text,client_id bigint,server_policy_id bigint,workstation_policy_id bigint,block_policy_inheritance bool DEFAULT false)`,
		`CREATE TABLE agents_agent (id bigint PRIMARY KEY,agent_id text,hostname text,site_id bigint,monitoring_type text,operating_system text,last_seen timestamptz,needs_reboot bool,offline_time bigint,overdue_time bigint,plat text,policy_id bigint,block_policy_inheritance bool DEFAULT false)`,
		`CREATE TABLE accounts_role_can_view_clients (role_id bigint,client_id bigint)`,
		`CREATE TABLE accounts_role_can_view_sites (role_id bigint,site_id bigint)`,
		`CREATE TABLE core_coresettings (id bigint,server_policy_id bigint,workstation_policy_id bigint)`,
		`CREATE TABLE automation_policy (id bigint,active bool,enforced bool)`,
		`CREATE TABLE automation_policy_excluded_agents (policy_id bigint,agent_id bigint)`,
		`CREATE TABLE automation_policy_excluded_sites (policy_id bigint,site_id bigint)`,
		`CREATE TABLE automation_policy_excluded_clients (policy_id bigint,client_id bigint)`,
		`CREATE TABLE scripts_script (id bigint,supported_platforms text[])`,
		`CREATE TABLE checks_check (id bigint,agent_id bigint,policy_id bigint,check_type text,disk text,ip text,svc_name text,script_id bigint,log_name text,event_id bigint)`,
		`CREATE TABLE checks_checkresult (id bigint,agent_id bigint,assigned_check_id bigint,status text)`,
		`CREATE TABLE winupdate_winupdate (agent_id bigint,installed bool,date_installed timestamptz,action text)`,
		`CREATE TABLE alerts_alert (id bigint,agent_id bigint,severity text,message text,alert_time timestamptz,resolved bool)`,
		`INSERT INTO clients_client (id,name) VALUES (1,'Client'),(2,'Empty')`,
		`INSERT INTO clients_site (id,name,client_id,server_policy_id) VALUES (11,'Visible',1,5),(12,'Hidden',1,NULL)`,
		`INSERT INTO accounts_role_can_view_sites VALUES (7,11)`,
		`INSERT INTO core_coresettings (id) VALUES (1)`,
		`INSERT INTO automation_policy VALUES (5,true,true)`,
		`INSERT INTO agents_agent (id,agent_id,hostname,site_id,monitoring_type,operating_system,last_seen,needs_reboot,offline_time,overdue_time,plat) VALUES (21,'agent-visible','Visible agent',11,'server','Windows',now(),true,5,30,'windows'),(22,'agent-hidden','Hidden agent',12,'server','Windows',now(),false,5,30,'windows')`,
		`INSERT INTO checks_check (id,agent_id,policy_id,check_type) VALUES (31,21,NULL,'cpuload'),(32,NULL,5,'cpuload'),(33,21,NULL,'memory')`,
		`INSERT INTO checks_checkresult VALUES (41,21,31,'failing'),(42,21,32,'passing')`,
		`INSERT INTO winupdate_winupdate VALUES (21,true,now(),'nothing'),(21,true,now()-interval '60 days','nothing'),(21,false,NULL,'approve'),(21,false,NULL,'inherit'),(22,false,NULL,'approve')`,
		`INSERT INTO alerts_alert SELECT i,21,'warning','visible',now(),false FROM generate_series(1,501) i`,
		`INSERT INTO alerts_alert VALUES (600,22,'error','hidden',now(),false),(601,21,'info','resolved',now(),true)`,
	} {
		if err := tx.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{DB: tx, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	p := &accounts.Principal{User: accounts.User{ID: 9}, Role: &accounts.Role{ID: 7, CanViewReports: true}}
	app := fiber.New(fiber.Config{ErrorHandler: s.handleError})
	app.Get("/client/:pk/health/", func(c fiber.Ctx) error { c.Locals("principal", p); return c.Next() }, requireReportRead, s.reportHealth)
	request := func(path string, want int) map[string]any {
		t.Helper()
		res, err := app.Test(httptest.NewRequest("GET", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != want {
			t.Fatalf("%s: %d %s", path, res.StatusCode, body)
		}
		var result map[string]any
		if want == 200 {
			if err := json.Unmarshal(body, &result); err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	report := request("/client/1/health/?template=health&monitoring_type=all&patch_days=30", 200)
	summary := report["summary"].(map[string]any)
	for key, want := range map[string]float64{"total_agents": 1, "servers": 1, "workstations": 0, "online": 1, "patches_pending": 1, "patches_installed_recently": 1, "patches_missing": 1, "checks_failing": 0, "open_alerts": 501, "needs_reboot": 1} {
		if summary[key] != want {
			t.Fatalf("%s=%v want %v", key, summary[key], want)
		}
	}
	if report["alerts_truncated"] != true || len(report["alerts"].([]any)) != 500 {
		t.Fatal("alert truncation/total mismatch")
	}
	agent := report["agents"].([]any)[0].(map[string]any)
	checks := agent["checks"].(map[string]any)
	if checks["passing"] != float64(1) || checks["pending"] != float64(1) || checks["failing"] != float64(0) {
		t.Fatalf("policy checks: %v", checks)
	}
	if agent["patches"].(map[string]any)["installed"] != float64(2) {
		t.Fatal("installed patch count")
	}
	request("/client/1/health/?site_id=12", 404)
	request("/client/2/health/", 403)
	request("/client/999/health/", 404)
	empty := request("/client/1/health/?monitoring_type=workstation", 200)
	if len(empty["agents"].([]any)) != 0 || empty["summary"].(map[string]any)["open_alerts"] != float64(0) {
		t.Fatal("agent filter did not scope alerts")
	}
	request("/client/1/health/?template=patches", 200)
	request("/client/1/health/?template=issues", 200)
	p.User.IsSuperuser = true
	request("/client/2/health/", 200)
}
