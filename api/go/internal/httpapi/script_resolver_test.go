package httpapi

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"regexp"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestScriptResolverBoundary(t *testing.T) {
	for _, field := range []string{"hostname", "site_id", "total_ram"} {
		if !scriptModelFields["agent"][field] {
			t.Fatal("missing supported field")
		}
	}
	for _, field := range []string{"password", "user", "checks", "get_agent_policies", "hostname;DELETE", "wmi_detail", "last_seen"} {
		if scriptModelFields["agent"][field] {
			t.Fatalf("unsafe field exposed %s", field)
		}
	}
	resolver := newScriptValueResolver(nil, "alert", 1)
	if _, err := resolver("alert.name"); !errors.Is(err, ErrUnsupportedScriptExpansion) {
		t.Fatal("unsupported root accepted")
	}
}

func TestScriptResolverContract(t *testing.T) {
	path := os.Getenv("TRMM_SCRIPT_RESOLVER_INPUT")
	if path == "" {
		t.Skip("isolated Django harness supplies fixtures")
	}
	dsn := os.Getenv("TRMM_SCRIPT_RESOLVER_DSN")
	u, err := url.Parse(dsn)
	if err != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || !regexp.MustCompile(`^go_contract_[a-f0-9]+$`).MatchString(u.Query().Get("search_path")) {
		t.Fatal("resolver contract requires isolated loopback contract schema")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal("could not open contract database")
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	tx := db.WithContext(context.Background()).Begin(&sql.TxOptions{ReadOnly: true})
	if tx.Error != nil {
		t.Fatal(tx.Error)
	}
	defer tx.Rollback()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Model, Expression string
		ID                int64
	}
	if err := json.Unmarshal(raw, &fixtures); err != nil {
		t.Fatal(err)
	}
	outputs := []map[string]any{}
	for _, fixture := range fixtures {
		resolve := newScriptValueResolver(tx, fixture.Model, fixture.ID)
		value, err := resolve(fixture.Expression)
		out := map[string]any{"value": value}
		if err != nil {
			kind := "database"
			switch {
			case errors.Is(err, ErrUnsupportedScriptExpansion):
				kind = "unsupported"
			case errors.Is(err, ErrScriptValueMissing):
				kind = "missing"
			case errors.Is(err, ErrScriptValueAmbiguous):
				kind = "ambiguous"
			}
			out = map[string]any{"error": kind}
		} else {
			args, err := expandScriptArgs([]string{"{{" + fixture.Expression + "}}"}, "powershell", resolve)
			if err != nil {
				t.Fatal("resolver output was not usable by argument expansion")
			}
			env, err := expandScriptEnv([]string{"VALUE={{" + fixture.Expression + "}}"}, "powershell", resolve)
			if err != nil {
				t.Fatal("resolver output was not usable by env expansion")
			}
			out["args"], out["env"] = args, env
		}
		outputs = append(outputs, out)
	}
	raw, err = json.Marshal(outputs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("TRMM_SCRIPT_RESOLVER_OUTPUT"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
