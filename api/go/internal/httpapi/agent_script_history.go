package httpapi

import (
	"encoding/json"
	"math/big"
	"time"

	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerScriptHistory(app *fiber.App) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/agents/scripthistory/", s.authenticate, require("can_list_agent_history"), s.scriptHistory)
}

func scriptHistoryLimit(raw string) (int, bool) {
	number, ok := registryPage(raw)
	if !ok {
		return 0, false
	}
	value, ok := new(big.Int).SetString(number.String(), 10)
	if !ok || value.Sign() < 0 {
		return 0, false
	}
	// PostgreSQL LIMIT is a signed bigint; reject overflow before executing SQL.
	maximum := int(^uint(0) >> 1)
	if !value.IsInt64() || value.Int64() > int64(maximum) {
		return 0, false
	}
	return int(value.Int64()), true
}

func scriptHistoryDate(raw string) (*time.Time, bool) {
	encoded, _ := json.Marshal(raw)
	value, problems := datetimeField(encoded)
	return value, len(problems) == 0 && value != nil
}

func scriptHistoryEntry(row historyRow, agentID string) fiber.Map {
	entry := historyEntry(row)
	out := fiber.Map{"agent_id": agentID}
	for _, key := range []string{"id", "time", "username", "script", "script_results", "agent", "script_name"} {
		if value, exists := entry[key]; exists {
			out[key] = value
		}
	}
	return out
}

func (s *Server) scriptHistory(c fiber.Ctx) error {
	query := s.DB.WithContext(c.Context()).Table("agents_agenthistory h").
		Joins("JOIN agents_agent a ON a.id=h.agent_id JOIN clients_site s ON s.id=a.site_id").
		Joins("LEFT JOIN scripts_script sc ON sc.id=h.script_id")
	// Scope before filtering and limiting; Django's global source leaks other clients.
	query = agentScope(query, c).Where("h.type = ?", "script_run")
	start, _ := lastQuery(c, "start")
	end, _ := lastQuery(c, "end")
	if start != "" && end != "" {
		lower, okStart := scriptHistoryDate(start)
		upper, okEnd := scriptHistoryDate(end)
		if !okStart || !okEnd {
			return c.Status(400).JSON("Invalid date range")
		}
		upperEnd := upper.Add(24 * time.Hour)
		if upperEnd.Year() > 9999 {
			return c.Status(400).JSON("Invalid date range")
		}
		query = query.Where("h.time BETWEEN ? AND ?", lower, upperEnd)
	}
	if name, _ := lastQuery(c, "scriptname"); name != "" {
		query = query.Where("sc.name = ?", name)
	}
	if raw, _ := lastQuery(c, "limit"); raw != "" {
		limit, ok := scriptHistoryLimit(raw)
		if !ok {
			return c.Status(400).JSON("Invalid limit")
		}
		query = query.Limit(limit)
	}
	rows, err := query.Select("h.id,h.time,h.username,h.script_id,h.script_results,h.agent_id,sc.name,a.agent_id").Order("h.time DESC").Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []fiber.Map{}
	for rows.Next() {
		var row historyRow
		var agentID string
		var scriptResults []byte
		if err := rows.Scan(&row.ID, &row.Time, &row.Username, &row.Script, &scriptResults, &row.Agent, &row.ScriptName, &agentID); err != nil {
			return err
		}
		row.ScriptResults = json.RawMessage(scriptResults)
		out = append(out, scriptHistoryEntry(row, agentID))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return c.JSON(out)
}
