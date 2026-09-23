package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/amidaware/tacticalrmm/api/go/internal/agentbus"
	"github.com/amidaware/tacticalrmm/api/go/internal/pep440"
	"gorm.io/gorm"
)

// Distinct from the pending-actions lock so the two one-shot jobs can coexist.
const AutoApproveLock int64 = 0x54524d4d41555044

const autoApproveMinVersion = "1.3.0"

type AutoApproveOptions struct {
	Now       time.Time
	DryRun    bool
	Disabled  bool
	ScanPause time.Duration
	Prune     func(tx *gorm.DB, agentPK int64) error
	Approve   func(tx *gorm.DB, agentID string) (int64, error)
}

type AutoApproveReport struct {
	Job            string `json:"job"`
	Selected       int    `json:"selected"`
	Approved       int    `json:"approved"`
	Changed        int64  `json:"changed"`
	ScanEligible   int    `json:"scan_eligible"`
	Published      int    `json:"published"`
	DryRun         bool   `json:"dry_run"`
	Disabled       bool   `json:"disabled"`
	AlreadyRunning bool   `json:"already_running"`
}

type autoApproveAgent struct {
	ID          int64
	AgentID     string
	Version     string
	LastSeen    *time.Time
	OfflineTime int64
	OverdueTime int64
}

type scanPublisher interface {
	Publish(ctx context.Context, subject string, payload map[string]any, timeout time.Duration) error
}

// AutoApproveUpdates mirrors winupdate.tasks.auto_approve_updates_task: prune and
// approve every agent under separate commits, then publish getwinupdates to online
// agents at or above 1.3.0 in chunks of 40. Approval errors are skipped like the
// source bare except; an invalid version on an otherwise online agent aborts the
// scan phase after approvals have already committed.
func AutoApproveUpdates(ctx context.Context, db *gorm.DB, bus scanPublisher, options AutoApproveOptions) (AutoApproveReport, error) {
	report := AutoApproveReport{Job: "auto-approve-win-updates", DryRun: options.DryRun, Disabled: options.Disabled}
	if options.Disabled {
		return report, nil
	}
	if options.Prune == nil || options.Approve == nil {
		return report, errors.New("prune and approve helpers are required")
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Year() < 1 || now.Year() > 9999 {
		return report, errors.New("job time is out of range")
	}
	pause := options.ScanPause
	if pause < 0 {
		return report, errors.New("scan pause must not be negative")
	}
	if pause == 0 && !options.DryRun {
		pause = time.Second
	}
	minVersion, err := pep440.Parse(autoApproveMinVersion)
	if err != nil {
		return report, errors.New("invalid minimum agent version")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	var acquired bool
	if err := db.WithContext(ctx).Raw("SELECT pg_try_advisory_lock(?)", AutoApproveLock).Scan(&acquired).Error; err != nil {
		return report, errors.New("acquire auto-approve job lock")
	}
	if !acquired {
		report.AlreadyRunning = true
		return report, nil
	}
	defer db.WithContext(context.Background()).Exec("SELECT pg_advisory_unlock(?)", AutoApproveLock)

	var agents []autoApproveAgent
	if err := db.WithContext(ctx).Table("agents_agent").Select("id,agent_id,version,last_seen,offline_time,overdue_time").Order("id").Find(&agents).Error; err != nil {
		return report, errors.New("read agents for auto-approve")
	}
	report.Selected = len(agents)

	var scanTargets []string
	for _, agent := range agents {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if !options.DryRun {
			// Source commits superseded cleanup even when approve_updates fails.
			if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				return options.Prune(tx, agent.ID)
			}); err != nil {
				return report, fmt.Errorf("prune superseded updates for agent %s", agent.AgentID)
			}
			var changed int64
			err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
				n, err := options.Approve(tx, agent.AgentID)
				if err != nil {
					return err
				}
				changed = n
				return nil
			})
			if err == nil {
				report.Changed += changed
			}
		}
		report.Approved++
		online, err := agentOnline(now, agent.LastSeen, agent.OfflineTime, agent.OverdueTime)
		if err != nil {
			return report, fmt.Errorf("invalid status timing for agent %s", agent.AgentID)
		}
		if !online {
			continue
		}
		version, err := pep440.Parse(agent.Version)
		if err != nil {
			return report, fmt.Errorf("invalid agent version for agent %s", agent.AgentID)
		}
		if pep440.Compare(version, minVersion) < 0 {
			continue
		}
		scanTargets = append(scanTargets, agent.AgentID)
	}
	report.ScanEligible = len(scanTargets)
	if options.DryRun || len(scanTargets) == 0 {
		return report, nil
	}
	if bus == nil {
		return report, errors.New("agent messaging is not configured")
	}
	for start := 0; start < len(scanTargets); start += 40 {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		end := start + 40
		if end > len(scanTargets) {
			end = len(scanTargets)
		}
		for _, agentID := range scanTargets[start:end] {
			if err := bus.Publish(ctx, agentID, map[string]any{"func": "getwinupdates"}, 10*time.Second); err != nil {
				var failure *agentbus.PublishError
				if errors.As(err, &failure) && failure.Ambiguous {
					return report, fmt.Errorf("ambiguous scan publish for agent %s", agentID)
				}
				return report, fmt.Errorf("publish scan for agent %s", agentID)
			}
			report.Published++
		}
		if end < len(scanTargets) && pause > 0 {
			timer := time.NewTimer(pause)
			select {
			case <-ctx.Done():
				timer.Stop()
				return report, ctx.Err()
			case <-timer.C:
			}
		}
	}
	return report, nil
}
