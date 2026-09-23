package httpapi

import (
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/gofiber/fiber/v3"
	"gorm.io/gorm"
)

func (s *Server) logout(c fiber.Ctx) error {
	if err := s.DB.WithContext(c.Context()).Delete(principal(c).Token).Error; err != nil {
		return err
	}
	return c.SendStatus(204)
}

func (s *Server) logoutAll(c fiber.Ctx) error {
	if err := s.DB.WithContext(c.Context()).Where("user_id = ?", principal(c).User.ID).Delete(&accounts.Token{}).Error; err != nil {
		return err
	}
	return c.SendStatus(204)
}

type userResponse struct {
	accounts.User
	LastLogin *string `json:"last_login"`
}

func (s *Server) user(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	var user accounts.User
	if err := s.DB.WithContext(c.Context()).First(&user, id).Error; err != nil {
		return lookupError(err, "User")
	}
	return c.JSON(userResponse{User: user, LastLogin: datetime(user.LastLogin)})
}

type sessionResponse struct {
	Digest  string  `json:"digest"`
	User    string  `json:"user"`
	Created *string `json:"created"`
	Expiry  *string `json:"expiry"`
}

func (s *Server) sessions(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	db := s.DB.WithContext(c.Context())
	var user accounts.User
	if err := db.First(&user, id).Error; err != nil {
		return lookupError(err, "User")
	}
	var tokens []accounts.Token
	if err := db.Where("user_id = ? AND expiry > ?", id, time.Now().UTC()).Find(&tokens).Error; err != nil {
		return err
	}
	response := make([]sessionResponse, 0, len(tokens))
	for _, token := range tokens {
		response = append(response, sessionResponse{token.Digest, user.Username, datetime(&token.Created), datetime(token.Expiry)})
	}
	return c.JSON(response)
}

func (s *Server) deleteSessions(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var user accounts.User
		if err := tx.First(&user, id).Error; err != nil {
			return lookupError(err, "User")
		}
		return tx.Where("user_id = ? AND expiry > ?", id, time.Now().UTC()).Delete(&accounts.Token{}).Error
	})
	if err != nil {
		return err
	}
	return c.JSON("ok")
}

func (s *Server) deleteSession(c fiber.Ctx) error {
	result := s.DB.WithContext(c.Context()).Where("digest = ?", c.Params("digest")).Delete(&accounts.Token{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return lookupError(gorm.ErrRecordNotFound, "AuthToken")
	}
	return c.JSON("ok")
}

type roleResponse struct {
	accounts.Role
	CreatedTime    *string `json:"created_time"`
	ModifiedTime   *string `json:"modified_time"`
	CanViewClients []int64 `json:"can_view_clients"`
	CanViewSites   []int64 `json:"can_view_sites"`
	UserCount      int64   `json:"user_count"`
}

func (s *Server) roles(c fiber.Ctx) error { return s.readRoles(c, false) }
func (s *Server) role(c fiber.Ctx) error  { return s.readRoles(c, true) }

func (s *Server) readRoles(c fiber.Ctx, single bool) error {
	db := s.DB.WithContext(c.Context())
	query := db.Model(&accounts.Role{})
	if single {
		id, err := identifier(c)
		if err != nil {
			return err
		}
		query = query.Where("id = ?", id)
	}
	var roles []accounts.Role
	if err := query.Find(&roles).Error; err != nil {
		return err
	}
	if single && len(roles) == 0 {
		return lookupError(gorm.ErrRecordNotFound, "Role")
	}
	response := make([]roleResponse, 0, len(roles))
	if len(roles) == 0 {
		return c.JSON(response)
	}
	ids := make([]int64, 0, len(roles))
	for _, role := range roles {
		ids = append(ids, role.ID)
	}
	var clients []struct{ RoleID, ClientID int64 }
	var sites []struct{ RoleID, SiteID int64 }
	var counts []struct{ RoleID, Count int64 }
	if err := db.Table("accounts_role_can_view_clients").Where("role_id IN ?", ids).Find(&clients).Error; err != nil {
		return err
	}
	if err := db.Table("accounts_role_can_view_sites").Where("role_id IN ?", ids).Find(&sites).Error; err != nil {
		return err
	}
	if err := db.Model(&accounts.User{}).Select("role_id, count(*) AS count").Where("role_id IN ?", ids).Group("role_id").Scan(&counts).Error; err != nil {
		return err
	}
	byClient, bySite, byCount := map[int64][]int64{}, map[int64][]int64{}, map[int64]int64{}
	for _, row := range clients {
		byClient[row.RoleID] = append(byClient[row.RoleID], row.ClientID)
	}
	for _, row := range sites {
		bySite[row.RoleID] = append(bySite[row.RoleID], row.SiteID)
	}
	for _, row := range counts {
		byCount[row.RoleID] = row.Count
	}
	for _, role := range roles {
		response = append(response, roleResponse{
			Role:        role,
			CreatedTime: datetime(role.CreatedTime), ModifiedTime: datetime(role.ModifiedTime),
			CanViewClients: append([]int64{}, byClient[role.ID]...),
			CanViewSites:   append([]int64{}, bySite[role.ID]...), UserCount: byCount[role.ID],
		})
	}
	if single {
		return c.JSON(response[0])
	}
	return c.JSON(response)
}
