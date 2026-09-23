package httpapi

import (
	"context"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/database"
	"gorm.io/gorm"
)

func TestSupersededUpdateIDs(t *testing.T) {
	ptr := func(s string) *string { return &s }
	for _, tc := range []struct {
		name   string
		titles []*string
		want   []int64
	}{
		{"normal", []*string{ptr("App (Version 1.2)"), ptr("App (Version 1.10)")}, []int64{1}},
		{"prefix matches newer first", []*string{ptr("App (Version 12)"), ptr("App (Version 2)")}, []int64{1}},
		{"Portuguese", []*string{ptr("App (VERSÃO 1rc1)"), ptr("App (Version 1)")}, []int64{1}},
		{"duplicates select same first", []*string{ptr("(Version 1)"), ptr("(Version 1)"), ptr("(Version 2)")}, []int64{1}},
		{"invalid skips whole group", []*string{ptr("(Version 1)"), ptr("(Version bananas)"), ptr("(Version 2)")}, []int64{}},
		{"missing skips whole group", []*string{ptr("(Version 1)"), nil}, []int64{}},
		{"no marker", []*string{ptr("(Version 1)"), ptr("App 2")}, []int64{}},
		{"local ordering", []*string{ptr("(Version 1+xyz)"), ptr("(Version 1+2)")}, []int64{1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := []supersedenceRow{}
			for i, title := range tc.titles {
				rows = append(rows, supersedenceRow{ID: int64(i + 1), KB: ptr("KB1"), Title: title})
			}
			if got := supersededUpdateIDs(rows); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	rows := []supersedenceRow{{1, nil, ptr("(Version 1)")}, {2, nil, ptr("(Version 2)")}, {3, ptr(""), ptr("(Version 1)")}}
	if got := supersededUpdateIDs(rows); !reflect.DeepEqual(got, []int64{1}) {
		t.Fatal(got)
	}
}

// Python runs this test-only bridge against its own disposable schema. It adds
// no production route or permanent executable, and always supplies a transaction.
func TestSupersedenceDatabaseContract(t *testing.T) {
	dsn := os.Getenv("TRMM_SUPERSEDENCE_DSN")
	if dsn == "" {
		t.Skip("isolated differential harness supplies DSN")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") {
		t.Fatal("only loopback test DB is allowed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := database.Open(ctx, dsn)
	if err != nil {
		t.Fatal("open contract database failed")
	}
	pool, _ := db.DB()
	defer pool.Close()
	var schema string
	if err := db.Raw("SELECT current_schema()").Scan(&schema).Error; err != nil || !strings.HasPrefix(schema, "go_contract_") {
		t.Fatal("only isolated contract schema is allowed")
	}
	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error { return pruneSupersededUpdates(tx, 31) }); err != nil {
		t.Fatal("prune failed; transaction rolled back")
	}
}
