package agentbus

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/ugorji/go/codec"
)

// Minimal local protocol peer; no real broker, credentials or agents involved.
func fakePeer(t *testing.T, mode string, reply []byte) (string, <-chan map[string]any) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	requests := make(chan map[string]any, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if mode == "silent-handshake" {
			io.Copy(io.Discard, conn)
			return
		}
		fmt.Fprint(conn, "INFO {\"server_id\":\"fixture\",\"version\":\"2.10.0\",\"proto\":1,\"headers\":true,\"max_payload\":2097152}\r\n")
		reader := bufio.NewReader(conn)
		sid := ""
		published := false
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			parts := strings.Fields(line)
			if len(parts) == 0 {
				continue
			}
			switch parts[0] {
			case "PING":
				if published && mode == "publish-no-pong" {
					continue
				}
				fmt.Fprint(conn, "PONG\r\n")
			case "SUB":
				sid = parts[len(parts)-1]
			case "PUB":
				if len(parts) != 4 && len(parts) != 3 {
					return
				}
				size, err := strconv.Atoi(parts[len(parts)-1])
				if err != nil {
					return
				}
				body := make([]byte, size+2)
				if _, err := io.ReadFull(reader, body); err != nil {
					return
				}
				var payload map[string]any
				if codec.NewDecoderBytes(body[:size], messageHandle()).Decode(&payload) != nil {
					return
				}
				requests <- payload
				published = true
				if mode == "publish-disconnect" {
					return
				}
				if len(parts) == 3 {
					if mode == "publish-denied" {
						fmt.Fprint(conn, "-ERR 'Permissions Violation for Publish to agent'\r\n")
					}
					continue // No reply subject: emulate a broker without subscribers.
				}
				switch mode {
				case "timeout":
					continue
				case "no-responders":
					header := "NATS/1.0 503\r\n\r\n"
					fmt.Fprintf(conn, "HMSG %s %s %d %d\r\n%s\r\n", parts[2], sid, len(header), len(header), header)
				default:
					fmt.Fprintf(conn, "MSG %s %s %d\r\n", parts[2], sid, len(reply))
					conn.Write(reply)
					fmt.Fprint(conn, "\r\n")
				}
			}
		}
	}()
	return "nats://" + listener.Addr().String(), requests
}

func TestPublishWithoutSubscriber(t *testing.T) {
	url, requests := fakePeer(t, "publish", nil)
	err := (&Client{URL: url}).Publish(context.Background(), "agent.fixture", map[string]any{
		"func": "getwinupdates", "items": []any{"ü", int64(-2), nil, true},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	payload := <-requests
	items := payload["items"].([]any)
	if payload["func"] != "getwinupdates" || items[0] != "ü" || items[1] != int64(-2) || items[2] != nil || items[3] != true {
		t.Fatal(payload)
	}
	if len(requests) != 0 {
		t.Fatal("publish retried")
	}
}

func TestPublishAmbiguousFailures(t *testing.T) {
	for _, mode := range []string{"publish-disconnect", "publish-no-pong", "cancel-after-publish", "publish-denied"} {
		t.Run(mode, func(t *testing.T) {
			peerMode := mode
			if mode == "cancel-after-publish" {
				peerMode = "publish-no-pong"
			}
			url, requests := fakePeer(t, peerMode, nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				result <- (&Client{URL: url}).Publish(ctx, "agent", map[string]any{"func": "test"}, 100*time.Millisecond)
			}()
			select {
			case <-requests:
			case <-time.After(time.Second):
				t.Fatal("publication not observed")
			}
			if mode == "cancel-after-publish" {
				cancel()
			}
			var err error
			select {
			case err = <-result:
			case <-time.After(time.Second):
				t.Fatal("flush not bounded")
			}
			var failure *PublishError
			if !errors.As(err, &failure) || !failure.Ambiguous {
				t.Fatalf("missing ambiguous delivery classification: %v", err)
			}
			want := ErrUnavailable
			if mode == "publish-no-pong" {
				want = ErrTimeout
			}
			if mode == "cancel-after-publish" {
				want = context.Canceled
			}
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
			if len(requests) != 0 {
				t.Fatal("publication retried")
			}
		})
	}
}

func TestPublishLocalBroker(t *testing.T) {
	endpoint := os.Getenv("TRMM_TEST_NATS_URL")
	if endpoint == "" {
		t.Skip("isolated broker not configured")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "nats" || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("TRMM_TEST_NATS_URL must be a credential-free isolated loopback broker URL")
	}
	nc, err := nats.Connect(endpoint, nats.UserInfo("tacticalrmm", "trmm-test-only"), nats.NoReconnect(), nats.Timeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	subject := nats.NewInbox()
	sub, err := nc.SubscribeSync(subject)
	if err != nil {
		t.Fatal(err)
	}
	if err := nc.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	c := &Client{URL: endpoint, User: "tacticalrmm", Password: "trmm-test-only"}
	if err := c.Publish(context.Background(), subject, map[string]any{"func": "fixture", "items": []any{int64(-2), "ü", nil}}, time.Second); err != nil {
		t.Fatal(err)
	}
	msg, err := sub.NextMsg(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	value, err := decodeReply(msg.Data)
	if err != nil || value.(map[string]any)["func"] != "fixture" {
		t.Fatal(value, err)
	}
	if _, err := sub.NextMsg(50 * time.Millisecond); !errors.Is(err, nats.ErrTimeout) {
		t.Fatal("duplicate publish", err)
	}
	if err := c.Publish(context.Background(), nats.NewInbox(), map[string]any{"func": "no-subscriber-fixture"}, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestPublishBeforeSendFailures(t *testing.T) {
	check := func(err error, want error) {
		t.Helper()
		var failure *PublishError
		if !errors.As(err, &failure) || failure.Ambiguous || !errors.Is(err, want) {
			t.Fatalf("expected known-unsent %v, got %#v", want, err)
		}
	}
	for _, subject := range []string{"", "*", "agent.>", "a b", "a\n", "a..b", ".a", "a.", "\xff"} {
		check((&Client{URL: "nats://127.0.0.1:1"}).Publish(context.Background(), subject, nil, time.Second), ErrUnavailable)
	}
	var missing *Client
	check(missing.Publish(context.Background(), "agent", nil, time.Second), ErrUnavailable)
	check((&Client{}).Publish(context.Background(), "agent", nil, time.Second), ErrUnavailable)
	c := &Client{URL: "nats://127.0.0.1:1"}
	check(c.Publish(context.Background(), "agent", nil, 0), ErrTimeout)
	check(c.Publish(context.Background(), "agent", nil, time.Second), ErrUnavailable)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	check(c.Publish(ctx, "agent", nil, time.Second), context.Canceled)
	for _, cancelled := range []bool{false, true} {
		url, _ := fakePeer(t, "silent-handshake", nil)
		ctx, cancel := context.WithCancel(context.Background())
		if cancelled {
			time.AfterFunc(20*time.Millisecond, cancel)
		}
		want := ErrTimeout
		if cancelled {
			want = context.Canceled
		}
		check((&Client{URL: url}).Publish(ctx, "agent", nil, 60*time.Millisecond), want)
		cancel()
	}
}

func TestRequestPythonMessagePack(t *testing.T) {
	// msgpack.packb({"status":"ok","items":[1,-2,None,True]})
	reply := []byte{0x82, 0xa6, 's', 't', 'a', 't', 'u', 's', 0xa2, 'o', 'k', 0xa5, 'i', 't', 'e', 'm', 's', 0x94, 1, 0xfe, 0xc0, 0xc3}
	url, requests := fakePeer(t, "reply", reply)
	c := Client{URL: url, User: "fixture", Password: "fixture-secret"}
	result, err := c.Request(context.Background(), "agent.fixture", map[string]any{"func": "test", "args": []any{"ü", int64(12)}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	row, ok := result.(map[string]any)
	if !ok || row["status"] != "ok" {
		t.Fatalf("wrong response shape %T", result)
	}
	items := row["items"].([]any)
	if len(items) != 4 || items[2] != nil || items[3] != true {
		t.Fatal(items)
	}
	payload := <-requests
	if payload["func"] != "test" || payload["args"].([]any)[0] != "ü" {
		t.Fatal("request codec mismatch")
	}
}

func TestRequestFailures(t *testing.T) {
	for _, mode := range []string{"timeout", "no-responders"} {
		t.Run(mode, func(t *testing.T) {
			url, _ := fakePeer(t, mode, nil)
			_, err := (&Client{URL: url}).Request(context.Background(), "agent", map[string]any{}, 40*time.Millisecond)
			if !errors.Is(err, ErrTimeout) {
				t.Fatal(err)
			}
		})
	}
	for _, reply := range [][]byte{{}, {0xc1}, {0xc0, 0xc0}, make([]byte, maxReplyBytes+1)} {
		url, _ := fakePeer(t, "reply", reply)
		_, err := (&Client{URL: url}).Request(context.Background(), "agent", map[string]any{}, time.Second)
		if !errors.Is(err, ErrInvalidReply) {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&Client{URL: "nats://127.0.0.1:1"}).Request(ctx, "agent", nil, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	for _, subject := range []string{"", "*", "agent.>", "a b", "a\n", "a..b", ".a", "a."} {
		if literalSubject(subject) {
			t.Errorf("accepted subject %q", subject)
		}
	}
}

func TestCancelSilentHandshake(t *testing.T) {
	url, _ := fakePeer(t, "silent-handshake", nil)
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(30*time.Millisecond, cancel)
	defer timer.Stop()
	started := time.Now()
	_, err := (&Client{URL: url}).Request(ctx, "agent", nil, time.Second)
	if !errors.Is(err, context.Canceled) || time.Since(started) > time.Second {
		t.Fatalf("cancellation did not bound handshake: %v", err)
	}
}

func TestDecodeReplyBounds(t *testing.T) {
	for _, raw := range [][]byte{{0x81, 1, 2}, {0xdd, 0xff, 0xff, 0xff, 0xff}, {0xd9, 3, 'a'}} {
		if _, err := decodeReply(raw); !errors.Is(err, ErrInvalidReply) {
			t.Fatalf("accepted malformed reply %x", raw)
		}
	}
	nested := append([]byte(strings.Repeat(string([]byte{0x91}), 70)), 0xc0)
	if _, err := decodeReply(nested); !errors.Is(err, ErrInvalidReply) {
		t.Fatal("accepted excessive nesting")
	}
}

func TestDeadlineClassification(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if _, err := (&Client{URL: "nats://127.0.0.1:1"}).Request(expired, "agent", nil, time.Second); !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
	url, _ := fakePeer(t, "silent-handshake", nil)
	ctx, cancelConnect := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelConnect()
	if _, err := (&Client{URL: url}).Request(ctx, "agent", nil, time.Second); !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
}

func TestDecodeReplyJSONCompatibility(t *testing.T) {
	for _, raw := range [][]byte{
		{0xcb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0}, // NaN
		{0xcb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0}, // +Inf
		{0xca, 0xff, 0x80, 0, 0},             // -Inf float32
		{0xa1, 0xff},                         // invalid UTF-8 value
		{0x81, 0xa1, 0xff, 0xc0},             // invalid UTF-8 key
		{0xd4, 1, 0},                         // extension
		{0x91, 0x81, 0xa1, 'x', 0xcb, 0x7f, 0xf8, 0, 0, 0, 0, 0, 0}, // nested NaN
	} {
		if _, err := decodeReply(raw); !errors.Is(err, ErrInvalidReply) {
			t.Fatalf("accepted non-JSON reply %x", raw)
		}
	}
	for _, raw := range [][]byte{{0xc0}, {0xc3}, {0x01}, {0xff}, {0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, {0xcb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0}, {0x90}, {0x80}} {
		if _, err := decodeReply(raw); err != nil {
			t.Fatalf("rejected JSON reply %x: %v", raw, err)
		}
	}
}
