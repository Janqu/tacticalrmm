package httpapi

import (
	"encoding/json"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerAgentTaskReads(app *fiber.App) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/agents/:agent_id/tasks/", s.authenticate,
		requireRead("can_list_autotasks", "can_manage_autotasks"), s.agentTasks)
}

func (s *Server) agentTasks(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	// Apply agent scope to HEAD too; avoid Django's cross-client HEAD permission gap.
	if err := s.hasPermOnAgent(c, id); err != nil {
		return err
	}
	db := s.DB.WithContext(c.Context())
	agent, err := resolveAgentPolicies(db, id)
	if err != nil {
		return err
	}
	// Resolve fresh database state instead of deserializing Django's cached Python models.
	tasks, err := loadAgentTaskRows(db.Table("autotasks_automatedtask t").Where("t.agent_id = ?", agent.ID))
	if err != nil {
		return err
	}
	for _, policy := range agent.Policies {
		inherited, err := loadAgentTaskRows(db.Table("autotasks_automatedtask t").Where("t.policy_id = ? AND ? = ANY(t.task_supported_platforms)", policy.ID, agent.Platform))
		if err != nil {
			return err
		}
		tasks = append(tasks, inherited...)
	}
	results, err := loadAgentTaskRows(db.Table("autotasks_taskresult t").Where("t.agent_id = ?", agent.ID))
	if err != nil {
		return err
	}
	byTask := make(map[string]map[string]any, len(results))
	for _, result := range results {
		key := result["task_id"].(json.Number).String()
		if err := serializeTaskResult(result); err != nil {
			return err
		}
		byTask[key] = result
	}
	for _, task := range tasks {
		key := task["id"].(json.Number).String()
		if err := serializeAutoTask(db, task); err != nil {
			return err
		}
		if result, ok := byTask[key]; ok {
			task["task_result"] = result
		}
	}
	return c.JSON(tasks)
}

func loadAgentTaskRows(query *gorm.DB) ([]map[string]any, error) {
	rows, err := query.Select("to_jsonb(t)").Order("t.id").Rows()
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		row, err := decodeRow(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func serializeTaskResult(row map[string]any) error {
	if err := taskDateFields(row, "last_run", "locked_at"); err != nil {
		return err
	}
	renameAlertFields(row, "agent", "task")
	return nil
}
