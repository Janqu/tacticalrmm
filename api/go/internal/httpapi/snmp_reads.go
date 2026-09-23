package httpapi

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) registerSNMPReads(app *fiber.App) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/qdt_snmp/devices/", s.authenticate, require("can_list_sites"), s.listSNMPDevices)
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/qdt_snmp/latest/", s.authenticate, require("can_list_sites"), s.latestSNMPReadings)
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/qdt_snmp/alerts/", s.authenticate, require("can_list_sites"), s.listSNMPAlerts)
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/qdt_snmp/presets/", s.authenticate, require("can_list_sites"), s.listSNMPPresets)
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/qdt_snmp/sites/:pk<regex(^[0-9]+$)>/probe/", s.authenticate, require("can_list_sites"), s.snmpSiteProbe)
}

// Project only SnmpDeviceSerializer's public fields; never serialize the raw
// database model, which contains the unmasked community and internal fields.
type snmpDeviceRow struct {
	ID             int64           `json:"id"`
	ProbeAgent     *int64          `json:"probe_agent" gorm:"column:probe_agent_id"`
	ProbeAgentName *string         `json:"probe_agent_name,omitempty"`
	Site           int64           `json:"site" gorm:"column:site_id"`
	SiteName       string          `json:"site_name"`
	ClientName     string          `json:"client_name"`
	Name           string          `json:"name"`
	DeviceType     string          `json:"device_type"`
	IP             string          `json:"ip"`
	Port           int64           `json:"port"`
	Community      string          `json:"community"`
	Enabled        bool            `json:"enabled"`
	Description    *string         `json:"description"`
	OfflineMinutes int64           `json:"offline_minutes"`
	MetricMap      json.RawMessage `json:"metric_map"`
	Thresholds     json.RawMessage `json:"thresholds"`
	EmailAlerts    bool            `json:"email_alerts"`
	MatrixChannels json.RawMessage `json:"matrix_channels"`
	ModelName      *string         `json:"model_name"`
	Serial         *string         `json:"serial"`
	LastSeen       *time.Time      `json:"last_seen"`
	LastError      *string         `json:"last_error"`
	SwitchSnapshot json.RawMessage `json:"switch_snapshot"`
	Status         string          `json:"status" gorm:"-"`
}

func (r *snmpDeviceRow) prepareResponse(now time.Time) {
	r.Community = maskToken(r.Community).(string)
	r.Status = "pending"
	if r.LastSeen != nil {
		r.Status = "offline"
		if r.LastSeen.After(now.Add(-time.Duration(r.OfflineMinutes) * time.Minute)) {
			r.Status = "online"
		}
	} else if r.LastError != nil && *r.LastError != "" {
		r.Status = "offline"
	}
}

func (s *Server) snmpDeviceQuery(c fiber.Ctx, filtered bool) (*gorm.DB, error) {
	query := s.DB.WithContext(c.Context()).Table("qdt_snmp_snmpdevice d").
		Joins("JOIN clients_site x ON x.id = d.site_id").
		Joins("JOIN clients_client parent ON parent.id = x.client_id")
	query = clientSiteScope(query, c, false, false)
	if !filtered {
		return query, nil
	}
	// Django gives site precedence when both filters are supplied.
	for _, filter := range []struct{ key, column string }{{"site", "d.site_id"}, {"client", "x.client_id"}} {
		if raw, present := lastQuery(c, filter.key); present {
			id, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				return nil, fiber.NewError(400, "Invalid "+filter.key+" identifier.")
			}
			query = query.Where(filter.column+" = ?", id)
			break
		}
	}
	return query, nil
}

func (s *Server) listSNMPDevices(c fiber.Ctx) error {
	query, err := s.snmpDeviceQuery(c, true)
	if err != nil {
		return err
	}
	query = query.Joins("LEFT JOIN agents_agent probe ON probe.id = d.probe_agent_id")
	rows := []snmpDeviceRow{}
	err = query.Select(`d.id, d.probe_agent_id, probe.hostname AS probe_agent_name,
		d.site_id, x.name AS site_name, parent.name AS client_name,
		d.name, d.device_type, d.ip, d.port, d.community, d.enabled, d.description,
		d.offline_minutes, d.metric_map, d.thresholds, d.email_alerts,
		d.model_name, d.serial, d.last_seen, d.last_error, d.switch_snapshot,
		COALESCE((SELECT jsonb_agg(m.matrixchannel_id ORDER BY m.matrixchannel_id)
		FROM qdt_snmp_snmpdevice_matrix_channels m WHERE m.snmpdevice_id = d.id), '[]'::jsonb) AS matrix_channels`).
		Order("parent.name, x.name, d.name").Find(&rows).Error
	if err != nil {
		return err
	}
	now := time.Now()
	for i := range rows {
		rows[i].prepareResponse(now)
	}
	return c.JSON(rows)
}

type snmpLatestReading struct {
	DeviceID  int64     `json:"-"`
	Metric    string    `json:"-"`
	Value     *float64  `json:"value"`
	Timestamp time.Time `json:"timestamp"`
}

func (s *Server) latestSNMPReadings(c fiber.Ctx) error {
	query, err := s.snmpDeviceQuery(c, true)
	if err != nil {
		return err
	}
	rows := []snmpLatestReading{}
	err = query.Joins("JOIN qdt_snmp_snmpreading r ON r.device_id = d.id").
		Select("DISTINCT ON (r.device_id, r.metric) r.device_id, r.metric, r.value, r.timestamp").
		Order("r.device_id, r.metric, r.timestamp DESC").Find(&rows).Error
	if err != nil {
		return err
	}
	return c.JSON(snmpLatestResponse(rows))
}

func snmpLatestResponse(rows []snmpLatestReading) map[string]map[string]snmpLatestReading {
	out := make(map[string]map[string]snmpLatestReading)
	for _, row := range rows {
		id := strconv.FormatInt(row.DeviceID, 10)
		if out[id] == nil {
			out[id] = make(map[string]snmpLatestReading)
		}
		out[id][row.Metric] = row
	}
	return out
}

type snmpAlertRow struct {
	Device      int64     `json:"device"`
	DeviceName  string    `json:"device_name"`
	ClientName  string    `json:"client_name"`
	SiteName    string    `json:"site_name"`
	Metric      string    `json:"metric"`
	Severity    string    `json:"severity"`
	CreatedTime time.Time `json:"created_time"`
}

func (s *Server) listSNMPAlerts(c fiber.Ctx) error {
	// Python returns all visible fleet alerts, independently of the UI's
	// selected client/site. Device visibility still applies to every row.
	query, err := s.snmpDeviceQuery(c, false)
	if err != nil {
		return err
	}
	rows := []snmpAlertRow{}
	err = query.Joins("JOIN qdt_snmp_snmpalert a ON a.device_id = d.id").
		Select(`a.device_id AS device, d.name AS device_name, parent.name AS client_name,
			x.name AS site_name, a.metric, a.severity, a.created_time`).
		Order("a.id").Find(&rows).Error
	if err != nil {
		return err
	}
	return c.JSON(rows)
}
