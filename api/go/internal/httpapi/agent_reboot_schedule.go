package httpapi

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strconv"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerScheduledReboot(app *fiber.App) {
	app.Patch("/agents/:agent_id/reboot/", s.authenticate, require("can_reboot_agents"), s.scheduleAgentReboot)
}

func (s *Server) scheduleAgentReboot(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	if err := s.hasPermOnAgent(c, id); err != nil {
		return err
	}
	pk, err := s.agentPK(c, id)
	if err != nil {
		return err
	}
	var agent struct{ Hostname, Plat, Zone string }
	if err := s.DB.WithContext(c.Context()).Table("agents_agent").Select("hostname,plat,COALESCE(time_zone,'') AS zone").Where("id = ?", pk).Scan(&agent).Error; err != nil {
		return err
	}
	if agent.Plat == "linux" || agent.Plat == "darwin" {
		return c.Status(400).JSON("Not currently implemented for " + agent.Plat)
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	input, err := jsonObject(c)
	if err != nil {
		return err
	}
	var text string
	if err := json.Unmarshal(input["datetime"], &text); err != nil {
		return c.Status(400).JSON("Invalid date")
	}
	wall, err := scheduledRebootDate(text)
	if err != nil {
		return c.Status(400).JSON("Invalid date")
	}
	var zone *time.Location
	if agent.Zone != "" {
		zone, err = time.LoadLocation(agent.Zone)
	} else {
		zone, err = loadDefaultTimezone(s.DB.WithContext(c.Context()))
	}
	if err != nil {
		return err
	}
	due, err := pendingWallTime(wall.Format("2006-01-02 15:04:05"), zone)
	if err != nil {
		return err
	}
	if time.Now().After(due) {
		return c.Status(400).JSON("Date cannot be set in the past")
	}
	name, err := scheduledRebootName()
	if err != nil {
		return err
	}
	reply, err := s.NATS.Request(c.Context(), id, scheduledRebootPayload(wall, name), 10*time.Second)
	if err != nil {
		switch {
		case errors.Is(err, agentbus.ErrTimeout):
			return c.Status(400).JSON("timeout")
		case errors.Is(err, agentbus.ErrUnavailable):
			return c.Status(400).JSON("natsdown")
		case errors.Is(err, agentbus.ErrInvalidReply):
			return fiber.NewError(502, "Invalid agent reply.")
		default:
			return err
		}
	}
	ack, ok := reply.(string)
	if !ok {
		return fiber.NewError(502, "Invalid agent reply.")
	}
	if ack != "ok" {
		return c.Status(400).JSON(ack)
	}
	details, err := json.Marshal(map[string]any{"taskname": name, "time": wall.Format("2006-01-02 15:04:05")})
	if err != nil {
		return err
	}
	// The remote task is already scheduled. A failed insert cannot undo it;
	// report that failure and never retry either the command or insertion.
	if err := s.DB.WithContext(c.Context()).Exec("INSERT INTO logs_pendingaction (agent_id,entry_time,action_type,status,details) VALUES (?, ?, 'schedreboot', 'pending', ?::jsonb)", pk, time.Now().UTC(), string(details)).Error; err != nil {
		return err
	}
	return c.JSON(fiber.Map{"time": wall.Format("January 02, 2006 at 03:04 PM"), "agent": agent.Hostname, "task_name": name})
}

var rebootDatePattern = regexp.MustCompile(`^(\d{4})-(\d{1,2})-(\d{1,2})T(\d{1,2}):(\d{1,2})$`)

func scheduledRebootDate(text string) (time.Time, error) {
	parts := rebootDatePattern.FindStringSubmatch(text)
	if parts == nil {
		return time.Time{}, errors.New("invalid reboot date")
	}
	values := make([]int, 5)
	for i := range values {
		values[i], _ = strconv.Atoi(parts[i+1])
	}
	wall := time.Date(values[0], time.Month(values[1]), values[2], values[3], values[4], 0, 0, time.UTC)
	if wall.Year() < 1 || wall.Year() != values[0] || int(wall.Month()) != values[1] || wall.Day() != values[2] || wall.Hour() != values[3] || wall.Minute() != values[4] || wall.Add(5*time.Minute).Year() > 9999 {
		return time.Time{}, errors.New("invalid reboot date")
	}
	return wall, nil
}

func scheduledRebootName() (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	name := make([]byte, 10)
	for i := range name {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		name[i] = letters[n.Int64()]
	}
	return "TacticalRMM_SchedReboot_" + string(name), nil
}

func scheduledRebootPayload(wall time.Time, name string) map[string]any {
	expire := wall.Add(5 * time.Minute)
	return map[string]any{"func": "schedtask", "schedtaskpayload": map[string]any{
		"type": "schedreboot", "enabled": true, "delete_expired_task_after": true,
		"start_when_available": false, "multiple_instances": 2, "trigger": "runonce", "name": name,
		"start_year": wall.Year(), "start_month": int(wall.Month()), "start_day": wall.Day(), "start_hour": wall.Hour(), "start_min": wall.Minute(),
		"expire_year": expire.Year(), "expire_month": int(expire.Month()), "expire_day": expire.Day(), "expire_hour": expire.Hour(), "expire_min": expire.Minute(),
	}}
}
