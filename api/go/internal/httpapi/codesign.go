package httpapi

import (
	"errors"

	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

// Only the database-backed CodeSign methods are ported; PATCH/POST need the
// external token service and the agent update task.
func (s *Server) getCodeSign(c fiber.Ctx) error {
	row, err := readRow(s.DB.WithContext(c.Context()), "core_codesigntoken", 0, false)
	if err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		// DRF serializes a missing instance as the serializer's initial data.
		return c.JSON(fiber.Map{"token": ""})
	}
	return c.JSON(fiber.Map{"id": row["id"], "token": row["token"]})
}

func (s *Server) deleteCodeSign(c fiber.Ctx) error {
	if err := s.DB.WithContext(c.Context()).Exec("DELETE FROM core_codesigntoken").Error; err != nil {
		return err
	}
	return c.JSON("ok")
}
