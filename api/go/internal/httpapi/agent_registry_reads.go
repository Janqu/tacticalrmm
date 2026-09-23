package httpapi

import (
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerRegistryReads(app *fiber.App) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/agents/:agent_id/registry/", s.authenticate, require("can_use_registry"), s.browseRegistry)
}

// This guard compares valid PEP 440 versions specifically against 2.10.0.
var registryVersionPattern = regexp.MustCompile(`(?i)^v?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)([-_.]?(?:alpha|beta|preview|pre|rc|a|b|c)[-_.]?[0-9]*)?((?:-[0-9]+)|(?:[-_.]?(?:post|rev|r)[-_.]?[0-9]*))?([-_.]?dev[-_.]?[0-9]*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)

func registryVersionSupported(value string) (bool, bool) {
	return versionAtLeast(value, []int64{2, 10, 0})
}

func versionAtLeast(value string, minimum []int64) (bool, bool) {
	parts := registryVersionPattern.FindStringSubmatch(strings.TrimSpace(value))
	if parts == nil {
		return false, false
	}
	if epoch, ok := new(big.Int).SetString(parts[1], 10); ok && epoch.Sign() > 0 {
		return true, true
	}
	release := strings.Split(parts[2], ".")
	for i := 0; i < len(release) || i < len(minimum); i++ {
		current := new(big.Int)
		if i < len(release) {
			current.SetString(release[i], 10)
		}
		target := int64(0)
		if i < len(minimum) {
			target = minimum[i]
		}
		if cmp := current.Cmp(big.NewInt(target)); cmp != 0 {
			return cmp > 0, true
		}
	}
	return parts[3] == "" && (parts[4] != "" || parts[5] == ""), true
}

func registryPage(raw string) (json.Number, bool) {
	raw = strings.TrimSpace(raw)
	var normalized strings.Builder
	digits := 0
	previousDigit := false
	for i, r := range raw {
		if (r == '+' || r == '-') && i == 0 {
			normalized.WriteRune(r)
			continue
		}
		if r == '_' {
			if !previousDigit {
				return "", false
			}
			previousDigit = false
			continue
		}
		n := -1
		if r >= '0' && r <= '9' {
			n = int(r - '0')
		} else {
			for _, part := range unicode.Nd.R16 {
				if r >= rune(part.Lo) && r <= rune(part.Hi) && (uint32(r)-uint32(part.Lo))%uint32(part.Stride) == 0 {
					n = int((uint32(r) - uint32(part.Lo)) / uint32(part.Stride) % 10)
					break
				}
			}
			if n < 0 {
				for _, part := range unicode.Nd.R32 {
					if uint32(r) >= part.Lo && uint32(r) <= part.Hi && (uint32(r)-part.Lo)%part.Stride == 0 {
						n = int((uint32(r) - part.Lo) / part.Stride % 10)
						break
					}
				}
			}
		}
		if n < 0 {
			return "", false
		}
		normalized.WriteByte(byte('0' + n))
		digits++
		previousDigit = true
	}
	if !previousDigit || digits > 4300 {
		return "", false
	}
	value, ok := new(big.Int).SetString(normalized.String(), 10)
	if !ok {
		return "", false
	}
	return json.Number(value.String()), true
}

func (s *Server) browseRegistry(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	if err := s.hasPermOnAgent(c, id); err != nil {
		return err
	}
	if c.Method() == fiber.MethodHead {
		return fiber.NewError(405, `Method "HEAD" not allowed.`)
	}
	pk, err := s.agentPK(c, id)
	if err != nil {
		return err
	}
	var version string
	if err := s.DB.WithContext(c.Context()).Table("agents_agent").Select("version").Where("id = ?", pk).Scan(&version).Error; err != nil {
		return err
	}
	supported, valid := registryVersionSupported(version)
	if !valid {
		return c.Status(400).JSON("Invalid agent version.")
	}
	if !supported {
		return c.Status(400).JSON("This feature requires agent version 2.10.0 or higher.")
	}
	path, present := lastQuery(c, "path")
	if !present {
		path = "Computer"
	}
	path = strings.TrimSpace(path)
	if strings.EqualFold(path, "computer") {
		path = "Computer"
	}
	pages := map[string]json.Number{}
	for key, fallback := range map[string]string{"page": "1", "page_size": "200"} {
		raw, present := lastQuery(c, key)
		if !present {
			raw = fallback
		}
		value, ok := registryPage(raw)
		if !ok {
			return c.Status(400).JSON("page and page_size must be integers")
		}
		pages[key] = value
	}
	if s.NATS == nil {
		return fiber.NewError(501, "Agent messaging is not configured.")
	}
	reply, err := s.NATS.Request(c.Context(), id, map[string]any{"func": "registry_browse", "payload": map[string]any{"path": path, "page": pages["page"].String(), "page_size": pages["page_size"].String()}}, 30*time.Second)
	status, body := registryBrowseResponse(reply, err, path, pages["page"], pages["page_size"])
	return c.Status(status).JSON(body)
}

func registryBrowseResponse(reply any, err error, path string, page, size json.Number) (int, any) {
	if errors.Is(err, agentbus.ErrTimeout) || errors.Is(err, agentbus.ErrUnavailable) {
		return 400, "Unable to contact the agent"
	}
	if err != nil {
		return 502, fiber.Map{"detail": "Invalid response from the agent."}
	}
	if text, ok := reply.(string); ok && (text == "timeout" || text == "natsdown") {
		return 400, "Unable to contact the agent"
	}
	data, ok := reply.(map[string]any)
	if !ok {
		return 502, fiber.Map{"detail": "Invalid response from the agent."}
	}
	if failure, present := data["error"]; present {
		switch failure.(type) {
		case map[string]any, []any:
			return 502, fiber.Map{"detail": "Invalid response from the agent."}
		}
		return 400, "Registry Browse failed: " + pyStr(failure)
	}
	out := fiber.Map{"path": path, "subkeys": []any{}, "values": []any{}, "has_more": false, "page": page, "page_size": size}
	for _, key := range []string{"path", "subkeys", "values", "has_more"} {
		if value, present := data[key]; present {
			out[key] = value
		}
	}
	return 200, out
}
