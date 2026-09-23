package httpapi

import (
	"encoding/json"

	"github.com/gofiber/fiber/v3"
)

func (s *Server) registerSoftwareReads(app *fiber.App) {
	app.Head("/software/chocos/", s.authenticate, func(c fiber.Ctx) error { return fiber.NewError(405, `Method "HEAD" not allowed.`) })
	app.Get("/software/chocos/", s.authenticate, s.readChocoCatalog)
	read := []string{fiber.MethodGet, fiber.MethodHead}
	app.Add(read, "/software/", s.authenticate, requireRead("can_list_software", "can_manage_software"), s.readInstalledSoftware)
	app.Add(read, "/software/:agent_id/", s.authenticate, requireRead("can_list_software", "can_manage_software"), s.readInstalledSoftware)
}

func (s *Server) readInstalledSoftware(c fiber.Ctx) error {
	id, err := agentID(c)
	if err != nil {
		return err
	}
	db := s.DB.WithContext(c.Context())
	query := db.Table("software_installedsoftware w").Joins("JOIN agents_agent a ON a.id=w.agent_id JOIN clients_site s ON s.id=a.site_id")
	if id != "" {
		if err := s.hasPermOnAgent(c, id); err != nil {
			return err
		}
		pk, err := s.agentPK(c, id)
		if err != nil {
			return err
		}
		query = query.Where("w.agent_id = ?", pk)
	} else {
		// Safe scoped HEAD replaces Django's missing-agent_id KeyError on this collection.
		query = agentScope(query, c)
	}
	rows, err := query.Select("jsonb_build_object('id',w.id,'agent',w.agent_id,'software',w.software)").Order("w.id").Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		out = append(out, raw)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return c.JSON(installedSoftwareResponse(out, id != ""))
}

func installedSoftwareResponse(rows []json.RawMessage, detail bool) any {
	if detail {
		if len(rows) == 1 {
			return rows[0]
		}
		return []any{}
	}
	return rows
}

func (s *Server) readChocoCatalog(c fiber.Ctx) error {
	rows, err := s.DB.WithContext(c.Context()).Raw("SELECT chocos FROM software_chocosoftware ORDER BY id DESC LIMIT 1").Rows()
	if err != nil {
		return err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return c.JSON(fiber.Map{})
	}
	var raw json.RawMessage
	if err := rows.Scan(&raw); err != nil {
		return err
	}
	return c.JSON(raw)
}
