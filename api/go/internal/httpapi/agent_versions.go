package httpapi

import "github.com/gofiber/fiber/v3"

func (s *Server) registerAgentVersions(app *fiber.App) {
	app.Add([]string{fiber.MethodGet, fiber.MethodHead}, "/agents/versions/", s.authenticate, requireRead("can_list_agents", "can_edit_agent"), s.agentVersions)
}

func (s *Server) agentVersions(c fiber.Ctx) error {
	if c.Method() == fiber.MethodHead {
		return fiber.NewError(405, `Method "HEAD" not allowed.`)
	}
	agents := []struct {
		ID       int64  `json:"id"`
		Hostname string `json:"hostname"`
		AgentID  string `json:"agent_id"`
		Client   string `json:"client"`
		Site     string `json:"site"`
	}{}
	db := s.DB.WithContext(c.Context()).Table("agents_agent a").
		Joins("JOIN clients_site s ON s.id = a.site_id").
		Joins("JOIN clients_client cl ON cl.id = s.client_id")
	if err := agentScope(db, c).Select("a.id,a.hostname,a.agent_id,cl.name AS client,s.name AS site").Scan(&agents).Error; err != nil {
		return err
	}
	return c.JSON(fiber.Map{"versions": []string{s.LatestAgentVersion}, "agents": agents})
}
