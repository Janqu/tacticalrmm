package mesh

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

func TestSyncProtocol(t *testing.T) {
	for _, mode := range []string{"apply", "dry-run", "rejected", "missing inventory", "paged inventory", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var writes []map[string]any
			server := httptest.NewServer(websocket.Handler(func(conn *websocket.Conn) {
				defer conn.Close()
				var request map[string]any
				if err := websocket.JSON.Receive(conn, &request); err != nil {
					return
				}
				if mode == "cancel" {
					var ignored any
					_ = websocket.JSON.Receive(conn, &ignored)
					return
				}
				action := request["action"].(string)
				// Unsolicited and unrelated messages must not acknowledge this request.
				_ = websocket.JSON.Send(conn, map[string]any{"action": action, "responseid": "another", "result": "denied"})
				r := map[string]any{"action": action, "responseid": request["responseid"]}
				switch action {
				case "users":
					delete(r, "responseid")
					if mode != "missing inventory" {
						r["users"] = []any{}
					}
				case "nodes":
					r["nodes"] = map[string]any{}
					if mode == "paged inventory" {
						r["limit"] = 100
					}
				default:
					mu.Lock()
					writes = append(writes, request)
					mu.Unlock()
					r["result"] = "ok"
					if mode == "rejected" {
						r["result"] = "do not log remote secrets"
					}
				}
				_ = websocket.JSON.Send(conn, r)
			}))
			defer server.Close()
			s := snapshot{Settings: settings{SyncMeshWithTRMM: true, MeshUsername: "Admin", MeshToken: strings.Repeat("01", 32)},
				Users: []user{{ID: 1, Username: "Alice A", FirstName: "Alice", IsSuperuser: true}}, Agents: []agent{{ID: 1, MeshNodeID: "ff"}}}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if mode == "cancel" {
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(ctx, 30*time.Millisecond)
				defer stop()
			}
			changes, err := synchronize(ctx, s, strings.Replace(server.URL, "http", "ws", 1), mode == "dry-run")
			wantError := mode != "apply" && mode != "dry-run"
			if (err != nil) != wantError {
				t.Fatalf("error = %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "remote secrets") {
				t.Fatal("leaked server error")
			}
			mu.Lock()
			defer mu.Unlock()
			switch mode {
			case "apply":
				if len(writes) != 3 || len(changes) != 3 {
					t.Fatalf("writes=%d changes=%d", len(writes), len(changes))
				}
				password := writes[0]["pass"].(string)
				if len(password) != 30 || strings.Count(strings.Map(func(r rune) rune {
					if strings.ContainsRune("!@#$", r) {
						return 'x'
					}
					return -1
				}, password), "x") != 1 {
					t.Fatal("invalid generated password")
				}
				if writes[1]["rights"] != float64(4088024) || writes[2]["realname"] != "Alice" {
					t.Fatal("incorrect MeshCentral permissions/display name")
				}
				encoded, _ := json.Marshal(changes)
				if strings.Contains(string(encoded), password) {
					t.Fatal("plan exposes credentials")
				}
			case "rejected":
				if len(writes) != 1 {
					t.Fatal("continued after failed mutation")
				}
			default:
				if len(writes) != 0 {
					t.Fatal("unexpected mutation")
				}
			}
		})
	}
}

func TestPlanRejectsInvalidInventoryBeforeWrites(t *testing.T) {
	for _, ids := range [][]string{{"invalid"}, {"ff", "ff"}, {" "}, {"f f"}} {
		s := snapshot{Settings: settings{SyncMeshWithTRMM: true}}
		for i, id := range ids {
			s.Agents = append(s.Agents, agent{ID: int64(i + 1), MeshNodeID: id})
		}
		changes, err := plan(s, nil, nil)
		if err == nil || len(changes) != 0 {
			t.Fatalf("invalid inventory accepted: %v", ids)
		}
	}
}

func TestExistingUnlinkedAccountIsReused(t *testing.T) {
	s := snapshot{Settings: settings{SyncMeshWithTRMM: true}, Users: []user{{ID: 1, Username: "admin", IsSuperuser: true}}, Agents: []agent{{ID: 1, MeshNodeID: "ff"}}}
	changes, err := plan(s, []meshUser{{ID: "user//admin___1"}}, nil)
	if err != nil || len(changes) != 1 || changes[0].Action != "adddeviceuser" {
		t.Fatalf("changes=%v error=%v", changes, err)
	}
}

func TestAuthKeyLengths(t *testing.T) {
	for _, length := range []int{0, 15, 16, 24, 31, 32, 96} {
		_, err := authToken("admin", strings.Repeat("01", length), time.Now())
		valid := length == 16 || length == 24 || length >= 32
		if (err == nil) != valid {
			t.Fatalf("key length %d: %v", length, err)
		}
	}
}
