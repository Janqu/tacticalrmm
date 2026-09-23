package httpapi

import (
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
)

func (s *Server) inventoryAssets(c fiber.Ctx) error {
	db := s.DB.WithContext(c.Context())
	sites := clientSiteScope(db.Table("clients_site x"), c, false, false).Select("x.id")
	clients := clientSiteScope(db.Table("clients_site x"), c, false, false).Select("x.client_id")
	query := db.Table("qdt_inventory_asset a").
		Joins("JOIN clients_site x ON x.id=a.site_id").Joins("JOIN clients_client parent ON parent.id=x.client_id").
		Joins("LEFT JOIN qdt_inventory_deviceprofile p ON p.id=a.profile_id").
		Joins("LEFT JOIN agents_agent g ON g.id=a.agent_id").
		Joins("LEFT JOIN qdt_snmp_snmpdevice d ON d.id=a.snmp_device_id").
		Where("a.site_id IN (?)", sites).
		Where("a.agent_id IS NULL OR g.site_id IN (?)", sites).
		Where("a.snmp_device_id IS NULL OR d.site_id IN (?)", sites).
		Where("a.profile_id IS NULL OR p.client_id IN (?)", clients)
	for _, key := range []string{"site", "profile"} {
		if raw, _ := lastQuery(c, key); raw != "" {
			value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
			if err != nil {
				return c.Status(400).JSON(fiber.Map{key: "Eine numerische ID ist erforderlich."})
			}
			query = query.Where("a."+key+"_id = ?", value)
		}
	}
	for _, key := range []string{"state", "category"} {
		if raw, _ := lastQuery(c, key); raw != "" {
			query = query.Where("a."+key+" = ?", raw)
		}
	}
	if raw, _ := lastQuery(c, "search"); strings.TrimSpace(raw) != "" {
		chars := []rune(strings.TrimSpace(raw))
		if len(chars) > 200 {
			chars = chars[:200]
		}
		search := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(string(chars)) + "%"
		query = query.Where("a.name ILIKE ? OR a.inventory_number ILIKE ? OR a.serial_number ILIKE ? OR a.assigned_to ILIKE ? OR a.location ILIKE ? OR a.model_name ILIKE ?", search, search, search, search, search, search)
	}
	var count int64
	if err := query.Count(&count).Error; err != nil {
		return err
	}
	pages := max(int64(1), (count+49)/50)
	page, err := pageNumber(c, pages)
	if err != nil {
		return err
	}
	rows, err := query.Select(`to_jsonb(a) || jsonb_build_object(
 'site_name',x.name,'client_id',x.client_id,'client_name',parent.name,
 'profile_name',p.name,'profile_defaults',p.defaults,'purchase_price',a.purchase_price::text,
 'agent_data', CASE WHEN g.id IS NULL THEN NULL ELSE jsonb_build_object(
 'agent_id',g.agent_id,'hostname',g.hostname,'plat',g.plat,'wmi_detail',g.wmi_detail,
 'operating_system',g.operating_system,'total_ram',g.total_ram,'public_ip',g.public_ip,
 'last_seen',g.last_seen,'offline_time',g.offline_time,'overdue_time',g.overdue_time) END,
 'snmp_data', CASE WHEN d.id IS NULL THEN NULL ELSE jsonb_build_object(
 'name',d.name,'model_name',d.model_name,'serial',d.serial,'ip',d.ip,
 'last_seen',d.last_seen,'offline_minutes',d.offline_minutes,'last_error',d.last_error) END)`).
		Order("a.inventory_number,a.id").Limit(50).Offset(int((page - 1) * 50)).Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	results := []map[string]any{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		row, err := decodeRow(raw)
		if err != nil {
			return err
		}
		results = append(results, inventoryAssetResponse(row, time.Now()))
	}
	if err := rows.Err(); err != nil {
		return err
	}
	var next, previous any
	if page < pages {
		next = pageLink(c, page+1)
	}
	if page > 1 {
		previous = pageLink(c, page-1)
	}
	return c.JSON(fiber.Map{"count": count, "next": next, "previous": previous, "results": results})
}

func inventoryAssetResponse(row map[string]any, now time.Time) map[string]any {
	result := map[string]any{}
	// Explicit public serializer fields exclude notification bookkeeping and
	// joined technical data that is only used to compute the detected summary.
	for _, key := range strings.Fields("id site_name client_id client_name inventory_number name category state manufacturer model_name serial_number location assigned_to supplier purchase_date purchase_price warranty_until maintenance_due documentation_url notes attributes version created_at updated_at") {
		result[key] = row[key]
	}
	for _, key := range []string{"created_at", "updated_at"} {
		if parsed := inventoryTime(row[key]); parsed != nil {
			result[key] = datetime(parsed)
		}
	}
	result["site"], result["profile"], result["snmp_device"] = row["site_id"], row["profile_id"], row["snmp_device_id"]
	if row["profile_id"] != nil {
		result["profile_name"] = row["profile_name"]
	}
	effective := map[string]any{}
	for _, key := range []string{"profile_defaults", "attributes"} {
		if attrs, ok := row[key].(map[string]any); ok {
			for k, v := range attrs {
				effective[k] = v
			}
		}
	}
	result["effective_attributes"] = effective
	result["agent"] = nil
	detected := map[string]any{}
	if g, ok := row["agent_data"].(map[string]any); ok {
		result["agent"], result["agent_id"] = g["agent_id"], g["agent_id"]
		plat, _ := g["plat"].(string)
		offline, _ := pyInt(g["offline_time"])
		overdue, _ := pyInt(g["overdue_time"])
		status := agentStatus(&agentListRow{LastSeen: inventoryTime(g["last_seen"]), OfflineTime: offline, OverdueTime: overdue}, now)
		detected = map[string]any{"source": "agent", "name": g["hostname"], "model": makeModel(plat, g["wmi_detail"]), "serial": serialNumber(plat, g["wmi_detail"]), "os": g["operating_system"], "ram_gb": g["total_ram"], "public_ip": g["public_ip"], "status": status, "last_seen": g["last_seen"]}
	} else if d, ok := row["snmp_data"].(map[string]any); ok {
		minutes, _ := pyInt(d["offline_minutes"])
		message, _ := d["last_error"].(string)
		device := snmpDeviceRow{LastSeen: inventoryTime(d["last_seen"]), OfflineMinutes: minutes, LastError: &message}
		device.prepareResponse(now)
		detected = map[string]any{"source": "snmp", "name": d["name"], "model": d["model_name"], "serial": d["serial"], "ip": d["ip"], "status": device.Status, "last_seen": d["last_seen"]}
	}
	result["detected"] = detected
	return result
}

func inventoryTime(value any) *time.Time {
	text, ok := value.(string)
	if !ok {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, text)
	if err != nil {
		return nil
	}
	return &parsed
}
