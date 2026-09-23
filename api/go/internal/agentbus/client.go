// Package agentbus implements the request/reply wire format shared by Django
// and TacticalRMM agents. It never retries commands after publication.
package agentbus

import (
	"context"
	"errors"
	"math"
	"net"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
)

var (
	ErrUnavailable  = errors.New("agent bus unavailable")
	ErrTimeout      = errors.New("agent request timed out")
	ErrInvalidReply = errors.New("invalid agent reply")
)

const maxReplyBytes = 1 << 20

type Client struct{ URL, User, Password string }

// PublishError records whether bytes may have been sent. Ambiguous failures must
// not be automatically retried: broker acknowledgement is not agent execution.
type PublishError struct {
	Err       error
	Ambiguous bool
}

func (e *PublishError) Error() string { return e.Err.Error() }
func (e *PublishError) Unwrap() error { return e.Err }

func literalSubject(subject string) bool {
	if subject == "" || !utf8.ValidString(subject) {
		return false
	}
	for _, r := range subject {
		if r == '*' || r == '>' || unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	for _, part := range strings.Split(subject, ".") {
		if part == "" {
			return false
		}
	}
	return true
}

// connectDialer binds both TCP connection setup and the subsequent NATS/TLS
// handshake to the caller's context. nats.Timeout alone cannot notice an early
// cancellation while reading a silent peer's INFO frame.
type connectDialer struct {
	ctx  context.Context
	stop func() bool
	conn net.Conn
}

func (d *connectDialer) Dial(network, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(d.ctx, network, address)
	if err != nil {
		return nil, err
	}
	if d.stop != nil {
		d.stop()
	}
	d.stop = context.AfterFunc(d.ctx, func() { conn.Close() })
	d.conn = conn
	return conn, nil
}

func messageHandle() *codec.MsgpackHandle {
	h := &codec.MsgpackHandle{}
	h.MapType = reflect.TypeOf(map[string]any{})
	h.RawToString = true
	h.MaxDepth = 64
	h.MaxInitLen = 1024
	return h
}

func decodeReply(data []byte) (any, error) {
	if len(data) == 0 || len(data) > maxReplyBytes {
		return nil, ErrInvalidReply
	}
	decoder := codec.NewDecoderBytes(data, messageHandle())
	var reply any
	if err := decoder.Decode(&reply); err != nil || decoder.NumBytesRead() != len(data) {
		return nil, ErrInvalidReply
	}
	if !jsonCompatible(reply) {
		return nil, ErrInvalidReply
	}
	return reply, nil
}

// Validate before HTTP handlers or JSON-backed model fields see the reply.
// MessagePack extensions and non-finite floats have no JSON counterpart; Go's
// JSON encoder silently replaces invalid UTF-8, which must not change agent data.
func jsonCompatible(value any) bool {
	switch v := value.(type) {
	case nil, bool, int64, uint64:
		return true
	case string:
		return utf8.ValidString(v)
	case float32:
		return !math.IsNaN(float64(v)) && !math.IsInf(float64(v), 0)
	case float64:
		return !math.IsNaN(v) && !math.IsInf(v, 0)
	case []any:
		for _, item := range v {
			if !jsonCompatible(item) {
				return false
			}
		}
		return true
	case map[string]any:
		for key, item := range v {
			if !utf8.ValidString(key) || !jsonCompatible(item) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (c *Client) Request(ctx context.Context, subject string, payload map[string]any, timeout time.Duration) (any, error) {
	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrTimeout
		}
		return nil, err
	}
	if c == nil || strings.TrimSpace(c.URL) == "" || !literalSubject(subject) {
		return nil, ErrUnavailable
	}
	if timeout <= 0 {
		return nil, ErrTimeout
	}
	var data []byte
	if err := codec.NewEncoderBytes(&data, messageHandle()).Encode(payload); err != nil {
		return nil, ErrUnavailable
	}
	nc, stop, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	defer stop()
	defer nc.Close()
	requestCtx, cancelRequest := context.WithTimeout(ctx, timeout)
	defer cancelRequest()
	reply, err := nc.RequestWithContext(requestCtx, subject, data)
	if err != nil {
		return nil, transportError(ctx, err)
	}
	return decodeReply(reply.Data)
}

func (c *Client) connect(ctx context.Context) (*nats.Conn, func() bool, error) {
	connectCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	dialer := &connectDialer{ctx: connectCtx}
	nc, err := nats.Connect(c.URL, nats.UserInfo(c.User, c.Password), nats.Timeout(3*time.Second), nats.NoReconnect(), nats.SetCustomDialer(dialer))
	if dialer.stop != nil {
		dialer.stop()
	}
	connectErr := connectCtx.Err()
	cancel()
	if err == nil && connectErr != nil {
		nc.Close()
		if errors.Is(connectErr, context.DeadlineExceeded) {
			return nil, nil, ErrTimeout
		}
		return nil, nil, connectErr
	}
	if err != nil {
		if errors.Is(connectErr, context.DeadlineExceeded) {
			return nil, nil, ErrTimeout
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, nil, ErrTimeout
		}
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, nats.ErrTimeout) {
			return nil, nil, ErrTimeout
		}
		var timeoutError net.Error
		if errors.As(err, &timeoutError) && timeoutError.Timeout() {
			return nil, nil, ErrTimeout
		}
		return nil, nil, ErrUnavailable
	}
	// Closing the socket directly also interrupts a blocked write holding NATS'
	// connection mutex; nc.Close alone could wait for that same mutex.
	stop := context.AfterFunc(ctx, func() { dialer.conn.Close() })
	return nc, stop, nil
}

func transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ErrTimeout
		}
		return ctx.Err()
	}
	if errors.Is(err, nats.ErrTimeout) || errors.Is(err, nats.ErrNoResponders) || errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	return ErrUnavailable
}

// Publish sends once and waits for a broker flush acknowledgement, even without
// subscribers. Its timeout bounds the entire connect/publish/flush operation.
func (c *Client) Publish(ctx context.Context, subject string, payload map[string]any, timeout time.Duration) error {
	if ctx.Err() != nil {
		return &PublishError{Err: transportError(ctx, ctx.Err())}
	}
	if c == nil || strings.TrimSpace(c.URL) == "" || !literalSubject(subject) {
		return &PublishError{Err: ErrUnavailable}
	}
	if timeout <= 0 {
		return &PublishError{Err: ErrTimeout}
	}
	var data []byte
	if err := codec.NewEncoderBytes(&data, messageHandle()).Encode(payload); err != nil {
		return &PublishError{Err: ErrUnavailable}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	nc, stop, err := c.connect(ctx)
	if err != nil {
		return &PublishError{Err: err}
	}
	defer stop()
	defer nc.Close()
	if ctx.Err() != nil {
		return &PublishError{Err: transportError(ctx, ctx.Err())}
	}
	// Once Publish is entered, conservatively classify any failure as ambiguous.
	if err := nc.Publish(subject, data); err != nil {
		return &PublishError{Err: transportError(ctx, err), Ambiguous: true}
	}
	if err := nc.FlushWithContext(ctx); err != nil {
		return &PublishError{Err: transportError(ctx, err), Ambiguous: true}
	}
	if err := nc.LastError(); err != nil {
		return &PublishError{Err: transportError(ctx, err), Ambiguous: true}
	}
	return nil
}
