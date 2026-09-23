package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func (s *Server) registerAgentCheckReads(app *fiber.App) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/agents/:agent_id/checks/", s.authenticate,
		requireRead("can_list_checks", "can_manage_checks"), s.readAgentChecks)
}

type inheritedCheck struct {
	ID        int64
	Agent     *int64 `gorm:"column:agent_id"`
	Policy    *int64 `gorm:"column:policy_id"`
	Type      string `gorm:"column:check_type"`
	Disk      *string
	IP        *string
	Service   *string `gorm:"column:svc_name"`
	Script    *int64  `gorm:"column:script_id"`
	LogName   *string
	EventID   *int64
	Platforms json.RawMessage
}

// selectInheritedChecks mirrors Policy.get_policy_checks: enforced policies,
// then direct checks, then ordinary policies. Only inherited winners are grouped;
// direct checks always remain in the response, including overridden ones.
func selectInheritedChecks(direct []inheritedCheck, byPolicy map[int64][]inheritedCheck, policies []agentInheritedPolicy, platform string) ([]int64, []int64, error) {
	enforced, ordinary := []inheritedCheck{}, []inheritedCheck{}
	for _, p := range policies {
		if p.Enforced {
			enforced = append(enforced, byPolicy[p.ID]...)
		} else {
			ordinary = append(ordinary, byPolicy[p.ID]...)
		}
	}
	if len(enforced)+len(ordinary) == 0 {
		return []int64{}, []int64{}, nil
	}
	candidates := append(append(enforced, direct...), ordinary...)
	seen := map[string]bool{}
	groups := map[string][]int64{}
	overridden := []int64{}
	for _, ch := range candidates {
		var parts []any
		switch ch.Type {
		case "diskspace":
			if platform != "windows" {
				continue
			}
			parts = []any{ch.Disk}
		case "ping":
			parts = []any{ch.IP}
		case "cpuload", "memory":
			if platform != "windows" {
				continue
			}
		case "winsvc":
			if platform != "windows" {
				continue
			}
			parts = []any{ch.Service}
		case "eventlog":
			if platform != "windows" {
				continue
			}
			parts = []any{ch.LogName, ch.EventID}
		case "script":
			if ch.Script == nil {
				return nil, nil, errors.New("script check has no script")
			}
			var supported []*string
			if len(ch.Platforms) > 0 {
				if err := json.Unmarshal(ch.Platforms, &supported); err != nil {
					return nil, nil, err
				}
			}
			matches := len(supported) == 0
			for _, p := range supported {
				if p != nil && *p == strings.ToLower(platform) {
					matches = true
				}
			}
			if !matches {
				continue
			}
			parts = []any{ch.Script}
		default:
			continue
		}
		raw, err := json.Marshal(parts)
		if err != nil {
			return nil, nil, err
		}
		key := ch.Type + ":" + string(raw)
		if seen[key] {
			if ch.Agent != nil {
				overridden = append(overridden, ch.ID)
			}
			continue
		}
		seen[key] = true
		if ch.Agent == nil {
			groups[ch.Type] = append(groups[ch.Type], ch.ID)
		}
	}
	out := []int64{}
	for _, kind := range []string{"diskspace", "ping", "cpuload", "memory", "winsvc", "script", "eventlog"} {
		out = append(out, groups[kind]...)
	}
	return out, overridden, nil
}

func (s *Server) readAgentChecks(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	// HEAD recomputes persistent flags too, so enforce scope for both methods.
	if err := s.hasPermOnAgent(c, id); err != nil {
		return err
	}
	var out []map[string]any
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var locked struct{ ID int64 }
		if err := tx.Table("agents_agent").Clauses(clause.Locking{Strength: "UPDATE"}).Where("agent_id = ?", id).Take(&locked).Error; err != nil {
			return lookupError(err, "Agent")
		}
		context, err := resolveAgentPolicies(tx, id)
		if err != nil {
			return err
		}
		policyIDs := []int64{}
		for _, p := range context.Policies {
			policyIDs = append(policyIDs, p.ID)
		}
		query := tx.Table("checks_check ch").Joins("LEFT JOIN scripts_script sc ON sc.id=ch.script_id").Where("ch.agent_id = ?", context.ID)
		if len(policyIDs) > 0 {
			query = query.Or("ch.policy_id IN ?", policyIDs)
		}
		all := []inheritedCheck{}
		if err := query.Select("ch.id,ch.agent_id,ch.policy_id,ch.check_type,ch.disk,ch.ip,ch.svc_name,ch.script_id,ch.log_name,ch.event_id,to_jsonb(sc.supported_platforms) AS platforms").Order("ch.id").Find(&all).Error; err != nil {
			return err
		}
		direct := []inheritedCheck{}
		byPolicy := map[int64][]inheritedCheck{}
		for _, ch := range all {
			if ch.Agent != nil && *ch.Agent == context.ID {
				direct = append(direct, ch)
			}
			if ch.Policy != nil {
				byPolicy[*ch.Policy] = append(byPolicy[*ch.Policy], ch)
			}
		}
		inherited, overridden, err := selectInheritedChecks(direct, byPolicy, context.Policies, context.Platform)
		if err != nil {
			return err
		}
		if err := tx.Table("checks_check").Where("agent_id = ?", context.ID).Update("overridden_by_policy", false).Error; err != nil {
			return err
		}
		if len(overridden) > 0 {
			if err := tx.Table("checks_check").Where("id IN ?", overridden).Update("overridden_by_policy", true).Error; err != nil {
				return err
			}
		}
		ids := make([]int64, 0, len(direct)+len(inherited))
		for _, ch := range direct {
			ids = append(ids, ch.ID)
		}
		ids = append(ids, inherited...)
		records := []checkReadRecord{}
		if len(ids) > 0 {
			if err := checkReadQuery(tx).Where("ch.id IN ?", ids).Select(checkReadSelect).Find(&records).Error; err != nil {
				return err
			}
		}
		serialized, err := serializeChecks(tx, records)
		if err != nil {
			return err
		}
		byID := map[string]map[string]any{}
		for _, row := range serialized {
			byID[fmt.Sprint(row["id"])] = row
		}
		rows, err := tx.Raw("SELECT to_jsonb(r) FROM checks_checkresult r WHERE r.agent_id = ? ORDER BY r.id", context.ID).Rows()
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			result, err := decodeCheckResult(raw)
			if err != nil {
				return err
			}
			if row := byID[fmt.Sprint(result["assigned_check"])]; row != nil {
				row["check_result"] = result
			}
		}
		if err := rows.Err(); err != nil {
			return err
		}
		out = make([]map[string]any, 0, len(ids))
		for _, pk := range ids {
			out = append(out, byID[fmt.Sprint(pk)])
		}
		return nil
	})
	if err != nil {
		return err
	}
	return c.JSON(out)
}
