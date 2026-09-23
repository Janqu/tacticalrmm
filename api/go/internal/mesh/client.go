package mesh

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/websocket"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var meshBase64 = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@$")

// authToken matches meshctrl's IV + GCM tag + ciphertext wire format.
func authToken(username, key string, now time.Time) (string, error) {
	decoded, err := hex.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid MeshCentral key")
	}
	if len(decoded) > 32 {
		decoded = decoded[:32]
	}
	block, err := aes.NewCipher(decoded)
	if err != nil {
		return "", errors.New("invalid MeshCentral key")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", errors.New("initialize MeshCentral encryption")
	}
	username = cases.Lower(language.Und).String(username)
	if !strings.Contains(username, "user/") {
		username = "user//" + username
	}
	message, err := json.Marshal(struct {
		UserID string `json:"userid"`
		Domain string `json:"domainid"`
		Time   int64  `json:"time"`
	}{username, "", now.Unix()})
	if err != nil {
		return "", errors.New("encode MeshCentral authentication")
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return "", errors.New("generate MeshCentral nonce")
	}
	sealed := gcm.Seal(nil, iv, message, nil)
	end := len(sealed) - gcm.Overhead()
	wire := append(iv, sealed[end:]...)
	wire = append(wire, sealed[:end]...)
	return meshBase64.EncodeToString(wire), nil
}

type client struct {
	baseURL, username, key string
}

type meshUser struct {
	ID       string `json:"_id"`
	RealName string `json:"realname"`
}

type meshNode struct {
	ID    string                     `json:"_id"`
	Links map[string]json.RawMessage `json:"links"`
}

type response struct {
	Action     string                `json:"action"`
	ResponseID string                `json:"responseid"`
	Result     string                `json:"result"`
	Users      []meshUser            `json:"users"`
	Nodes      map[string][]meshNode `json:"nodes"`
	Limit      int                   `json:"limit"`
	Skip       int                   `json:"skip"`
}

func (c client) request(ctx context.Context, payload map[string]any) (response, error) {
	var result response
	action, _ := payload["action"].(string)
	u, err := url.Parse(c.baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "ws" && u.Scheme != "wss") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return result, errors.New("invalid MESH_WS_URL: expected ws/wss base URL without credentials or query")
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/control.ashx"
	token, err := authToken(c.username, c.key, time.Now())
	if err != nil {
		return result, err
	}
	u.RawQuery = url.Values{"auth": {token}}.Encode()
	origin := "https://" + u.Host
	if u.Scheme == "ws" {
		origin = "http://" + u.Host
	}
	config, err := websocket.NewConfig(u.String(), origin)
	if err != nil {
		return result, errors.New("configure MeshCentral connection")
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	conn, err := config.DialContext(ctx)
	if err != nil {
		// Dial errors contain the authentication URL; never return them to logs.
		return result, fmt.Errorf("MeshCentral %s: connection failed", action)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return result, errors.New("set MeshCentral request deadline")
	}
	conn.MaxPayloadBytes = 100 << 20
	payload["responseid"] = "meshctrl"
	if err := websocket.JSON.Send(conn, payload); err != nil {
		return result, fmt.Errorf("MeshCentral %s: send failed", action)
	}
	for {
		result = response{}
		if err := websocket.JSON.Receive(conn, &result); err != nil {
			return result, fmt.Errorf("MeshCentral %s: receive failed", action)
		}
		// MeshCentral's successful users response omits responseid. Each call
		// has its own connection, so the action still identifies that response.
		usersWithoutID := action == "users" && result.ResponseID == ""
		if result.Action != action || (result.ResponseID != "meshctrl" && !usersWithoutID) {
			continue
		}
		if action == "users" || action == "nodes" {
			if result.Result != "" && result.Result != "ok" {
				return result, fmt.Errorf("MeshCentral %s: rejected", action)
			}
			if (action == "users" && result.Users == nil) || (action == "nodes" && result.Nodes == nil) {
				return result, fmt.Errorf("MeshCentral %s: missing inventory", action)
			}
			if action == "nodes" && (result.Limit > 0 || result.Skip > 0) {
				return result, errors.New("MeshCentral paginated node inventories are not supported")
			}
		} else if result.Result != "ok" {
			return result, fmt.Errorf("MeshCentral %s: rejected", action)
		}
		return result, nil
	}
}
