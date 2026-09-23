package httpapi

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerPendingActions(app *fiber.App) {
	read := []string{fiber.MethodGet, fiber.MethodHead}
	app.Add(read, "/logs/pendingactions/", s.authenticate, s.pendingActions)
	app.Add(read, "/agents/:agent_id/pendingactions/", s.authenticate, s.pendingActions)
	app.Delete("/logs/pendingactions/:pk<regex(^[0-9]+$)>/", s.authenticate, s.deletePendingAction)
}

type pendingActionRow struct {
	row                                   map[string]any
	agentID, hostname, client, site, zone string
}

func (s *Server) pendingActions(c fiber.Ctx) error {
	permission := "can_list_pendingactions"
	if c.Method() != fiber.MethodGet {
		permission = "can_manage_pendingactions"
	}
	if !principal(c).Can(permission) {
		return errForbidden()
	}
	id, err := agentID(c)
	if err != nil {
		return err
	}
	if id != "" {
		// Also scope HEAD: Django's management branch skips this check.
		if err := s.hasPermOnAgent(c, id); err != nil {
			return err
		}
		if _, err := s.agentPK(c, id); err != nil {
			return err
		}
	}
	result := []map[string]any{}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		query := tx.Table("logs_pendingaction p").Joins("JOIN agents_agent a ON a.id=p.agent_id JOIN clients_site s ON s.id=a.site_id JOIN clients_client cl ON cl.id=s.client_id")
		if id != "" {
			query = query.Where("a.agent_id = ?", id)
		} else {
			query = agentScope(query, c)
		}
		rows, err := query.Select("to_jsonb(p),a.agent_id,a.hostname,cl.name,s.name,COALESCE(a.time_zone,'')").Order("p.id").Rows()
		if err != nil {
			return err
		}
		entries := []pendingActionRow{}
		for rows.Next() {
			var raw []byte
			var entry pendingActionRow
			if err := rows.Scan(&raw, &entry.agentID, &entry.hostname, &entry.client, &entry.site, &entry.zone); err != nil {
				rows.Close()
				return err
			}
			entry.row, err = decodeRow(raw)
			if err != nil {
				rows.Close()
				return err
			}
			entries = append(entries, entry)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		var defaultZone *time.Location
		for _, entry := range entries {
			if entry.row["action_type"] == "schedreboot" && entry.row["status"] == "pending" {
				value, err := pendingDetail(entry.row, "time")
				if err != nil {
					return err
				}
				text, ok := value.(string)
				if !ok {
					return fmt.Errorf("invalid scheduled reboot time")
				}
				var zone *time.Location
				if entry.zone != "" {
					zone, err = time.LoadLocation(entry.zone)
				} else {
					if defaultZone == nil {
						defaultZone, err = loadDefaultTimezone(tx)
					}
					zone = defaultZone
				}
				if err != nil {
					return err
				}
				due, err := pendingWallTime(text, zone)
				if err != nil {
					return err
				}
				if time.Now().After(due) {
					if err := tx.Table("logs_pendingaction").Where("id = ? AND status = ?", entry.row["id"], "pending").Update("status", "completed").Error; err != nil {
						return err
					}
					entry.row["status"] = "completed"
				}
			}
			row, err := serializePendingAction(entry)
			if err != nil {
				return err
			}
			result = append(result, row)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return c.JSON(result)
}

func pendingDetail(row map[string]any, key string) (any, error) {
	details, ok := row["details"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("pending action details are not an object")
	}
	value, ok := details[key]
	if !ok {
		return nil, fmt.Errorf("pending action detail %s is missing", key)
	}
	return value, nil
}

func pendingDescription(row map[string]any) (any, error) {
	switch row["action_type"] {
	case "schedreboot":
		return "Device pending reboot", nil
	case "agentupdate":
		value, err := pendingDetail(row, "version")
		if err != nil {
			return nil, err
		}
		return "Agent update to " + pyStr(value), nil
	case "chocoinstall":
		value, err := pendingDetail(row, "name")
		if err != nil {
			return nil, err
		}
		return pyStr(value) + " software install", nil
	case "runcmd", "runscript", "runpatchscan", "runpatchinstall":
		return row["action_type"], nil
	}
	return nil, nil
}

func serializePendingAction(entry pendingActionRow) (map[string]any, error) {
	row := entry.row
	var due any = "On next checkin"
	switch row["action_type"] {
	case "schedreboot":
		value, err := pendingDetail(row, "time")
		if err != nil {
			return nil, err
		}
		due = value
	case "agentupdate":
		due = "Next update cycle"
	case "chocoinstall":
		due = "ASAP"
	}
	description, err := pendingDescription(row)
	if err != nil {
		return nil, err
	}
	if err := logTimestamp(row); err != nil {
		return nil, err
	}
	renameAlertFields(row, "agent")
	row["hostname"], row["client"], row["site"] = entry.hostname, entry.client, entry.site
	row["due"], row["description"] = due, description
	return row, nil
}

func (s *Server) deletePendingAction(c fiber.Ctx) error {
	if !principal(c).Can("can_manage_pendingactions") {
		return errForbidden()
	}
	id, err := identifier(c)
	if err != nil {
		return err
	}
	if id == 0 {
		return lookupError(gorm.ErrRecordNotFound, "PendingAction")
	}
	message := ""
	var rejected *string
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		row, err := readRow(tx, "logs_pendingaction", id, true)
		if err != nil {
			return lookupError(err, "PendingAction")
		}
		var agent struct{ AgentID, Hostname string }
		if err := tx.Table("agents_agent").Select("agent_id,hostname").Where("id = ?", row["agent_id"]).Scan(&agent).Error; err != nil {
			return err
		}
		if err := s.hasPermOnAgent(c, agent.AgentID); err != nil {
			return err
		}
		// Authorize and lock before contacting the agent. Never run the
		// expiry-on-read hook during cancellation, including failure paths.
		if row["action_type"] == "schedreboot" {
			if s.NATS == nil {
				return fiber.NewError(501, "Scheduled reboot cancellation requires the NATS agent transport.")
			}
			taskname, err := pendingTaskName(row)
			if err != nil {
				return err
			}
			reply, err := s.NATS.Request(c.Context(), agent.AgentID, map[string]any{
				"func": "delschedtask", "schedtaskpayload": map[string]any{"name": taskname},
			}, 10*time.Second)
			if err != nil {
				if errors.Is(err, agentbus.ErrTimeout) {
					text := "timeout"
					rejected = &text
				}
				if errors.Is(err, agentbus.ErrUnavailable) {
					text := "natsdown"
					rejected = &text
				}
				if errors.Is(err, agentbus.ErrInvalidReply) {
					return fiber.NewError(502, "Invalid agent reply.")
				}
				return err
			}
			ack, ok := reply.(string)
			if !ok {
				return fiber.NewError(502, "Invalid agent reply.")
			}
			if ack != "ok" {
				rejected = &ack
				return errors.New("agent rejected scheduled reboot cancellation")
			}
		}
		description, err := pendingDescription(row)
		if err != nil {
			return err
		}
		// A DB failure retains this row, but cannot undo an already acknowledged
		// remote cancellation. Surface the failure; never retry the command here.
		if err := tx.Exec("DELETE FROM logs_pendingaction WHERE id = ?", id).Error; err != nil {
			return err
		}
		message = agent.Hostname + ": " + pyStr(description) + " was cancelled"
		return nil
	})
	if rejected != nil {
		return c.Status(400).JSON(*rejected)
	}
	if err != nil {
		return err
	}
	return c.JSON(message)
}

func pendingTaskName(row map[string]any) (string, error) {
	value, err := pendingDetail(row, "taskname")
	text, ok := value.(string)
	if err != nil || !ok || strings.TrimSpace(text) == "" {
		return "", validationError{"taskname": {"A non-empty scheduled task name is required."}}
	}
	return text, nil
}

// Python datetime.replace(tzinfo=ZoneInfo(...)) uses fold=0. Go's Date chooses
// differently in some DST folds/gaps; inspect the adjacent offsets explicitly.
func pendingWallTime(text string, zone *time.Location) (time.Time, error) {
	wall, err := time.Parse("2006-1-2 15:4:5", text)
	if err != nil {
		return time.Time{}, err
	}
	if wall.Year() < 1 {
		return time.Time{}, fmt.Errorf("invalid scheduled reboot year")
	}
	offsets := map[int]bool{}
	for _, shift := range []time.Duration{-48 * time.Hour, 0, 48 * time.Hour} {
		_, offset := wall.Add(shift).In(zone).Zone()
		offsets[offset] = true
	}
	var exact, after time.Time
	var gap time.Duration
	for offset := range offsets {
		instant := wall.Add(-time.Duration(offset) * time.Second)
		local := instant.In(zone)
		localWall := time.Date(local.Year(), local.Month(), local.Day(), local.Hour(), local.Minute(), local.Second(), 0, time.UTC)
		delta := localWall.Sub(wall)
		if delta == 0 && (exact.IsZero() || instant.Before(exact)) {
			exact = instant
		}
		if delta > 0 && (after.IsZero() || delta < gap) {
			after, gap = instant, delta
		}
	}
	if !exact.IsZero() {
		return exact, nil
	}
	if !after.IsZero() {
		return after, nil
	}
	return time.Time{}, fmt.Errorf("cannot resolve scheduled reboot wall time")
}
