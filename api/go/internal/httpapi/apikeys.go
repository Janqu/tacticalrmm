package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/accounts"
	"github.com/amidaware/tacticalrmm/api/go/internal/audit"
	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type apiKeyResponse struct {
	ID           int64   `json:"id"`
	Name         string  `json:"name"`
	Key          string  `json:"key"`
	User         int64   `json:"user"`
	Username     string  `json:"username"`
	Expiration   *string `json:"expiration"`
	CreatedBy    *string `json:"created_by"`
	ModifiedBy   *string `json:"modified_by"`
	CreatedTime  *string `json:"created_time"`
	ModifiedTime *string `json:"modified_time"`
}

func (s *Server) apiKeys(c fiber.Ctx) error {
	var rows []struct {
		accounts.APIKey
		Username string
	}
	err := s.DB.WithContext(c.Context()).Table("accounts_apikey AS k").
		Select("k.*, u.username").Joins("JOIN accounts_user u ON u.id = k.user_id").Scan(&rows).Error
	if err != nil {
		return err
	}
	response := make([]apiKeyResponse, 0, len(rows))
	for _, row := range rows {
		response = append(response, apiKeyResponse{
			ID: row.ID, Name: row.Name, Key: row.Key, User: row.UserID, Username: row.Username,
			Expiration: datetime(row.Expiration), CreatedBy: row.CreatedBy, ModifiedBy: row.ModifiedBy,
			CreatedTime: datetime(row.CreatedTime), ModifiedTime: datetime(row.ModifiedTime),
		})
	}
	return c.JSON(response)
}

func (s *Server) addAPIKey(c fiber.Ctx) error    { return s.saveAPIKey(c, false) }
func (s *Server) updateAPIKey(c fiber.Ctx) error { return s.saveAPIKey(c, true) }

func (s *Server) saveAPIKey(c fiber.Ctx, update bool) error {
	var id int64
	if update {
		var err error
		id, err = identifier(c)
		if err != nil {
			return err
		}
	}
	err := s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		key := accounts.APIKey{}
		var before map[string]any
		if update {
			if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&key, id).Error; err != nil {
				return lookupError(err, "APIKey")
			}
			var err error
			before, err = apiKeyAuditValue(tx, key)
			if err != nil {
				return err
			}
		}
		input, err := jsonObject(c)
		if err != nil {
			return err
		}
		if err := validateAPIKey(tx, input, &key, update); err != nil {
			return err
		}
		actor := principal(c).User.Username
		if key.CreatedBy == nil || *key.CreatedBy == "" {
			key.CreatedBy = &actor
		}
		key.ModifiedBy = &actor
		now := time.Now().UTC()
		key.ModifiedTime = &now
		after, err := apiKeyAuditValue(tx, key)
		if err != nil {
			return err
		}
		if update {
			if !reflect.DeepEqual(before, after) {
				if err := writeAPIKeyAudit(tx, c, "modify", fmt.Sprintf("APIKey object (%d)", key.ID), before, after, &id); err != nil {
					return err
				}
			}
			return tx.Model(&key).Select("name", "user_id", "expiration", "created_by", "modified_by", "modified_time").Updates(&key).Error
		}
		key.Key, err = accounts.GenerateAPIKey()
		if err != nil {
			return err
		}
		key.CreatedTime = &now
		if err := writeAPIKeyAudit(tx, c, "add", "APIKey object (None)", nil, after, nil); err != nil {
			return err
		}
		return tx.Create(&key).Error
	})
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "23505" && strings.Contains(pgError.ConstraintName, "name") {
			return validationError{"name": {"api key with this name already exists."}}
		}
		return err
	}
	if update {
		return c.JSON("The API Key was edited")
	}
	return c.JSON("The API Key was added")
}

func (s *Server) deleteAPIKey(c fiber.Ctx) error {
	id, err := identifier(c)
	if err != nil {
		return err
	}
	err = s.DB.WithContext(c.Context()).Transaction(func(tx *gorm.DB) error {
		var key accounts.APIKey
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&key, id).Error; err != nil {
			return lookupError(err, "APIKey")
		}
		before, err := apiKeyAuditValue(tx, key)
		if err != nil {
			return err
		}
		if err := tx.Delete(&key).Error; err != nil {
			return err
		}
		return writeAPIKeyAudit(tx, c, "delete", "APIKey object (None)", before, nil, &id)
	})
	if err != nil {
		return err
	}
	return c.JSON("The API Key was deleted")
}

func validateAPIKey(tx *gorm.DB, input map[string]json.RawMessage, key *accounts.APIKey, partial bool) error {
	problems := validationError{}
	if raw, ok := input["name"]; ok {
		value, messages := charField(raw, 25, false, false)
		if len(messages) > 0 {
			problems["name"] = messages
		} else {
			var count int64
			if err := tx.Model(&accounts.APIKey{}).Where("name = ? AND id <> ?", *value, key.ID).Count(&count).Error; err != nil {
				return err
			}
			if count > 0 {
				problems["name"] = []string{"api key with this name already exists."}
			}
			key.Name = *value
		}
	} else if !partial {
		problems["name"] = []string{"This field is required."}
	}
	if raw, ok := input["user"]; ok {
		id, messages := relatedID(raw)
		if len(messages) > 0 {
			problems["user"] = messages
		} else {
			var count int64
			if err := tx.Model(&accounts.User{}).Where("id = ?", id).Count(&count).Error; err != nil {
				return err
			}
			if count == 0 {
				problems["user"] = []string{fmt.Sprintf("Invalid pk \"%d\" - object does not exist.", id)}
			}
			key.UserID = id
		}
	} else if !partial {
		problems["user"] = []string{"This field is required."}
	}
	if raw, ok := input["expiration"]; ok {
		value, messages := datetimeField(raw)
		if len(messages) > 0 {
			problems["expiration"] = messages
		} else {
			key.Expiration = value
		}
	}
	for _, field := range []string{"created_by", "modified_by"} {
		if raw, ok := input[field]; ok {
			value, messages := charField(raw, 255, true, true)
			if len(messages) > 0 {
				problems[field] = messages
			} else if field == "created_by" {
				key.CreatedBy = value
			}
		}
	}
	if len(problems) > 0 {
		return problems
	}
	return nil
}

func apiKeyAuditValue(tx *gorm.DB, key accounts.APIKey) (map[string]any, error) {
	var user accounts.User
	if err := tx.First(&user, key.UserID).Error; err != nil {
		return nil, err
	}
	return map[string]any{"name": key.Name, "username": user.Username, "expiration": datetime(key.Expiration)}, nil
}

func writeAPIKeyAudit(tx *gorm.DB, c fiber.Ctx, action, object string, before, after map[string]any, id *int64) error {
	actor := principal(c).User.Username
	view := "GetAddAPIKeys"
	kwargs := map[string]any{}
	if id != nil {
		view = "GetUpdateDeleteAPIKey"
		kwargs["pk"] = *id
	}
	verb := map[string]string{"add": "added", "modify": "modified", "delete": "deleted"}[action]
	return audit.Write(tx, audit.Entry{
		Username: actor, Action: action, ObjectType: "apikey",
		BeforeValue: before, AfterValue: after, Message: actor + " " + verb + " apikey " + object,
		DebugInfo: map[string]any{"url": c.Path(), "method": c.Method(), "view_class": view,
			"view_func": view, "view_args": []any{}, "view_kwargs": kwargs, "ip": c.IP()},
	})
}
