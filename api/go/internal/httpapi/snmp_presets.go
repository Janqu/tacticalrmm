package httpapi

import (
	"encoding/json"
	"time"

	"github.com/gofiber/fiber/v3"
)

type snmpPresetRow struct {
	ID          int64           `json:"id"`
	Name        string          `json:"name"`
	DeviceType  string          `json:"device_type"`
	MetricMap   json.RawMessage `json:"metric_map"`
	Thresholds  json.RawMessage `json:"thresholds"`
	CreatedTime time.Time       `json:"created_time"`
}

// Matches qdt_snmp/presets.py, including its distinct built-in response fields.
func builtinSNMPPresets(deviceType string) []any {
	all := []fiber.Map{
		{"id": "builtin-usw", "name": "Ubiquiti UniFi USW – automatische Ports", "device_type": "switch", "vendor": "ubiquiti", "metric_map": fiber.Map{}, "thresholds": fiber.Map{}},
		{"id": "builtin-ilo", "name": "HPE iLO/ProLiant-Grundwerte", "device_type": "server", "vendor": "ilo", "built_in": true,
			"metric_map": fiber.Map{"health.overall": fiber.Map{"oid": "1.3.6.1.4.1.232.6.1.3"}, "health.thermal": fiber.Map{"oid": "1.3.6.1.4.1.232.6.2.6.1"}, "health.fan": fiber.Map{"oid": "1.3.6.1.4.1.232.6.2.6.4"}, "health.power_supply": fiber.Map{"oid": "1.3.6.1.4.1.232.6.2.9.1"}}, "thresholds": fiber.Map{}},
		{"id": "builtin-idrac", "name": "Dell iDRAC-Grundwerte", "device_type": "server", "vendor": "idrac", "built_in": true,
			"metric_map": fiber.Map{"idrac.overall": fiber.Map{"oid": "1.3.6.1.4.1.674.10892.5.2.1.0"}, "idrac.storage": fiber.Map{"oid": "1.3.6.1.4.1.674.10892.5.2.3.0"}}, "thresholds": fiber.Map{}},
	}
	out := []any{}
	for _, preset := range all {
		if deviceType == "" || preset["device_type"] == deviceType {
			out = append(out, preset)
		}
	}
	return out
}

func (s *Server) listSNMPPresets(c fiber.Ctx) error {
	deviceType, _ := lastQuery(c, "device_type")
	query := s.DB.WithContext(c.Context()).Table("qdt_snmp_snmpdevicepreset")
	if deviceType != "" {
		query = query.Where("device_type = ?", deviceType)
	}
	rows := []snmpPresetRow{}
	if err := query.Select("id, name, device_type, metric_map, thresholds, created_time").Order("device_type, name").Find(&rows).Error; err != nil {
		return err
	}
	out := builtinSNMPPresets(deviceType)
	for _, row := range rows {
		out = append(out, row)
	}
	return c.JSON(out)
}
