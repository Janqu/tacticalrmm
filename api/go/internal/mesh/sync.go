package mesh

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gorm.io/gorm"
)

type settings struct {
	SyncMeshWithTRMM                         bool `gorm:"column:sync_mesh_with_trmm"`
	MeshUsername, MeshToken, MeshCompanyName string
}

type user struct {
	ID, RoleID                             int64
	Username, FirstName, LastName          string
	IsSuperuser, RoleSuperuser, CanUseMesh bool
}

type agent struct {
	ID, SiteID, ClientID int64
	MeshNodeID           string
}

type scope struct{ RoleID, ClientID, SiteID int64 }

type snapshot struct {
	Settings       settings
	Users          []user
	Agents         []agent
	Clients, Sites []scope
}

// Change is a secret-free description suitable for reviewing a dry run.
type Change struct {
	Action   string   `json:"action"`
	ID       string   `json:"id"`
	Users    []string `json:"users,omitempty"`
	Name     string   `json:"name,omitempty"`
	username string
}

var managedUser = regexp.MustCompile(`___\p{Nd}+`)

var ErrAlreadyRunning = errors.New("MeshCentral synchronization already running")

func load(db *gorm.DB) (snapshot, error) {
	var s snapshot
	err := db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Table("core_coresettings").Order("id").Take(&s.Settings).Error; err != nil {
			return err
		}
		if !s.Settings.SyncMeshWithTRMM {
			return nil
		}
		if err := tx.Table("accounts_user AS u").Select(`u.id, u.username, u.first_name, u.last_name, u.is_superuser,
			COALESCE(u.role_id, 0) AS role_id, COALESCE(r.is_superuser, false) AS role_superuser,
			COALESCE(r.can_use_mesh, false) AS can_use_mesh`).
			Joins("LEFT JOIN accounts_role AS r ON r.id = u.role_id").
			Where("u.agent_id IS NULL AND NOT u.is_installer_user AND u.is_active AND NOT u.block_dashboard_login").Order("u.id").Scan(&s.Users).Error; err != nil {
			return err
		}
		if err := tx.Table("agents_agent AS a").Select("a.id, a.mesh_node_id, a.site_id, s.client_id").
			Joins("JOIN clients_site AS s ON s.id = a.site_id").Where("a.mesh_node_id IS NOT NULL AND a.mesh_node_id <> ''").Order("a.id").Scan(&s.Agents).Error; err != nil {
			return err
		}
		if err := tx.Table("accounts_role_can_view_clients").Scan(&s.Clients).Error; err != nil {
			return err
		}
		return tx.Table("accounts_role_can_view_sites").Scan(&s.Sites).Error
	}, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	return s, err
}

func displayName(u user, company string) string {
	name := u.FirstName
	if u.LastName != "" {
		name += " " + u.LastName
	}
	if name != "" && company != "" {
		return name + " - " + company
	}
	return name + company
}

func permitted(u user, a agent, s snapshot) bool {
	if u.IsSuperuser || u.RoleSuperuser {
		return true
	}
	if !u.CanUseMesh {
		return false
	}
	scoped := false
	// ponytail: linear scope scans; index by role if large scope lists become a bottleneck.
	for _, v := range s.Clients {
		if v.RoleID == u.RoleID {
			scoped = true
			if v.ClientID == a.ClientID {
				return true
			}
		}
	}
	for _, v := range s.Sites {
		if v.RoleID == u.RoleID {
			scoped = true
			if v.SiteID == a.SiteID {
				return true
			}
		}
	}
	return !scoped
}

func difference(a, b map[string]bool) []string {
	out := []string{}
	for id := range a {
		if !b[id] {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

func plan(s snapshot, users []meshUser, groups map[string][]meshNode) ([]Change, error) {
	changes := []Change{}
	existing := map[string]meshUser{}
	for _, u := range users {
		if u.ID == "" {
			return nil, errors.New("MeshCentral returned a user without an ID")
		}
		if managedUser.MatchString(u.ID) {
			existing[u.ID] = u
		}
	}
	if !s.Settings.SyncMeshWithTRMM {
		ids := map[string]bool{}
		for id := range existing {
			ids[id] = true
		}
		for _, id := range difference(ids, nil) {
			changes = append(changes, Change{Action: "deleteuser", ID: id})
		}
		return changes, nil
	}
	wanted := map[string]user{}
	source := map[string]map[string]bool{}
	for _, a := range s.Agents {
		// Python bytes.fromhex permits ASCII whitespace between byte pairs.
		parts := strings.FieldsFunc(a.MeshNodeID, func(r rune) bool { return strings.ContainsRune(" \t\n\r\v\f", r) })
		for _, part := range parts {
			if len(part)%2 != 0 {
				return nil, fmt.Errorf("agent %d has an invalid MeshCentral node ID", a.ID)
			}
		}
		hexID := strings.Join(parts, "")
		decoded, err := hex.DecodeString(hexID)
		if err != nil || len(decoded) == 0 {
			return nil, fmt.Errorf("agent %d has an invalid MeshCentral node ID", a.ID)
		}
		nodeID := "node//" + meshBase64.EncodeToString(decoded)
		if _, ok := source[nodeID]; ok {
			return nil, errors.New("duplicate MeshCentral node ID in agent inventory")
		}
		source[nodeID] = map[string]bool{}
		for _, u := range s.Users {
			if !permitted(u, a, s) {
				continue
			}
			id := "user//" + cases.Lower(language.Und).String(strings.ReplaceAll(u.Username, " ", "")) + "___" + strconv.FormatInt(u.ID, 10)
			source[nodeID][id] = true
			wanted[id] = u
		}
	}
	target := map[string]map[string]bool{}
	linked := map[string]bool{}
	for _, nodes := range groups {
		for _, n := range nodes {
			if n.ID == "" {
				return nil, errors.New("MeshCentral returned a node without an ID")
			}
			if _, ok := target[n.ID]; ok {
				return nil, errors.New("duplicate MeshCentral node in remote inventory")
			}
			target[n.ID] = map[string]bool{}
			for id := range n.Links {
				if managedUser.MatchString(id) {
					target[n.ID][id] = true
					linked[id] = true
				}
			}
		}
	}
	desired := map[string]bool{}
	for id := range wanted {
		desired[id] = true
	}
	deleted := map[string]bool{}
	for _, id := range difference(desired, nil) {
		if _, ok := existing[id]; !ok {
			changes = append(changes, Change{Action: "adduser", ID: id, username: wanted[id].Username})
		}
	}
	for _, id := range difference(linked, desired) {
		deleted[id] = true
		changes = append(changes, Change{Action: "deleteuser", ID: id})
	}
	nodeIDs := map[string]bool{}
	for id := range source {
		nodeIDs[id] = true
	}
	for _, id := range difference(nodeIDs, nil) {
		for uid := range deleted {
			delete(target[id], uid)
		}
		if add := difference(source[id], target[id]); len(add) > 0 {
			changes = append(changes, Change{Action: "adddeviceuser", ID: id, Users: add})
		}
		if remove := difference(target[id], source[id]); len(remove) > 0 {
			changes = append(changes, Change{Action: "removedeviceuser", ID: id, Users: remove})
		}
	}
	for _, id := range difference(desired, nil) {
		name := displayName(wanted[id], s.Settings.MeshCompanyName)
		if existing[id].RealName != name {
			changes = append(changes, Change{Action: "edituser", ID: id, Name: name})
		}
	}
	return changes, nil
}

func randomChars(alphabet string, length int) (string, error) {
	out := make([]byte, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", errors.New("generate MeshCentral credentials")
		}
		out[i] = alphabet[n.Int64()]
	}
	return string(out), nil
}

func (c client) apply(ctx context.Context, change Change) error {
	p := map[string]any{"action": change.Action}
	switch change.Action {
	case "adduser":
		const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		random, err := randomChars(alphabet, 40)
		if err != nil {
			return err
		}
		special, err := randomChars("!@#$", 1)
		if err != nil {
			return err
		}
		position, err := rand.Int(rand.Reader, big.NewInt(30))
		if err != nil {
			return errors.New("generate MeshCentral password")
		}
		i := int(position.Int64())
		password := random[:i] + special + random[i:29]
		prefix := strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsNumber(r) {
				return r
			}
			return -1
		}, change.username)
		p["username"] = strings.TrimPrefix(change.ID, "user//")
		p["email"] = prefix + "." + random[29:35] + "@tacticalrmm-do-not-change-" + random[35:] + ".local"
		p["pass"] = password
		p["resetNextLogin"], p["randomPassword"], p["removeEvents"], p["emailVerified"] = false, false, false, true
	case "deleteuser":
		p["userid"] = change.ID
	case "edituser":
		p["id"], p["realname"] = change.ID, change.Name
	case "adddeviceuser":
		names := make([]string, len(change.Users))
		for i, id := range change.Users {
			names[i] = strings.TrimPrefix(id, "user//")
		}
		p["nodeid"], p["usernames"], p["rights"], p["remove"] = change.ID, names, 4088024, false
	case "removedeviceuser":
		p["action"], p["nodeid"], p["userids"], p["rights"], p["remove"] = "adddeviceuser", change.ID, change.Users, 0, true
	default:
		return errors.New("unknown MeshCentral change")
	}
	_, err := c.request(ctx, p)
	return err
}

func synchronize(ctx context.Context, s snapshot, baseURL string, dryRun bool) ([]Change, error) {
	c := client{baseURL, s.Settings.MeshUsername, s.Settings.MeshToken}
	users, err := c.request(ctx, map[string]any{"action": "users"})
	if err != nil {
		return nil, err
	}
	var nodes response
	if s.Settings.SyncMeshWithTRMM {
		nodes, err = c.request(ctx, map[string]any{"action": "nodes"})
		if err != nil {
			return nil, err
		}
	}
	changes, err := plan(s, users.Users, nodes.Nodes)
	if err != nil || dryRun {
		return changes, err
	}
	chunk := 375
	switch n := len(s.Agents); {
	case n <= 250:
		chunk = 150
	case n <= 500:
		chunk = 275
	case n <= 800:
		chunk = 300
	case n <= 1000:
		chunk = 340
	}
	changedNodes, lastNode := 0, ""
	for _, change := range changes {
		if change.Action == "adddeviceuser" || change.Action == "removedeviceuser" {
			if change.ID != lastNode {
				if changedNodes > 0 && changedNodes%chunk == 0 {
					timer := time.NewTimer(7 * time.Second)
					select {
					case <-ctx.Done():
						timer.Stop()
						return changes, ctx.Err()
					case <-timer.C:
					}
				}
				changedNodes++
				lastNode = change.ID
			}
		}
		if err := c.apply(ctx, change); err != nil {
			return changes, err
		}
	}
	return changes, nil
}

// Run reserves one PostgreSQL connection for a session-scoped advisory lock.
// The inventory is read in one snapshot; no database transaction spans network IO.
func Run(ctx context.Context, db *gorm.DB, baseURL string, dryRun bool) (changes []Change, err error) {
	err = db.WithContext(ctx).Connection(func(conn *gorm.DB) (runErr error) {
		const lockID int64 = 0x54524d4d4d455348
		var acquired bool
		if err := conn.Raw("SELECT pg_try_advisory_lock(?)", lockID).Scan(&acquired).Error; err != nil {
			return errors.New("acquire MeshCentral synchronization lock")
		}
		if !acquired {
			return ErrAlreadyRunning
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var released bool
			if err := conn.WithContext(cleanup).Raw("SELECT pg_advisory_unlock(?)", lockID).Scan(&released).Error; err != nil || !released {
				runErr = errors.Join(runErr, errors.New("release MeshCentral synchronization lock"))
			}
		}()
		s, err := load(conn)
		if err != nil {
			return errors.New("read MeshCentral synchronization inventory")
		}
		changes, err = synchronize(ctx, s, baseURL, dryRun)
		return err
	})
	return changes, err
}
