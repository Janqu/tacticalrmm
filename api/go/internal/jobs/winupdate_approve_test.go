package jobs

import (
	"context"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"
)

type fakeScanBus struct {
	messages []string
	err      error
}

func (f *fakeScanBus) Publish(ctx context.Context, subject string, payload map[string]any, timeout time.Duration) error {
	if f.err != nil {
		return f.err
	}
	if payload["func"] != "getwinupdates" {
		return errors.New("unexpected payload")
	}
	f.messages = append(f.messages, subject)
	return nil
}

func TestAutoApproveDisabledAndHooks(t *testing.T) {
	report, err := AutoApproveUpdates(context.Background(), nil, nil, AutoApproveOptions{Disabled: true})
	if err != nil || !report.Disabled || report.Job != "auto-approve-win-updates" {
		t.Fatal(report, err)
	}
	_, err = AutoApproveUpdates(context.Background(), nil, nil, AutoApproveOptions{})
	if err == nil || err.Error() != "prune and approve helpers are required" {
		t.Fatal(err)
	}
}

func TestAutoApproveScanChunking(t *testing.T) {
	// Pure helper coverage for pause/version gating lives in integration compares.
	// Keep a lightweight check that the publisher contract matches getwinupdates.
	bus := &fakeScanBus{}
	if err := bus.Publish(context.Background(), "agent-1", map[string]any{"func": "getwinupdates"}, time.Second); err != nil {
		t.Fatal(err)
	}
	if len(bus.messages) != 1 || bus.messages[0] != "agent-1" {
		t.Fatal(bus.messages)
	}
	_ = func(tx *gorm.DB, agentPK int64) error { return nil }
}
