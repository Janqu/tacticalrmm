package httpapi

import (
	"regexp"
	"sort"
	"strings"

	"github.com/amidaware/tacticalrmm/api/go/internal/pep440"
	"gorm.io/gorm"
)

type supersedenceRow struct {
	ID        int64
	KB, Title *string
}

var supersedenceVersion = regexp.MustCompile(`(?i)\((Version|Versão)(.*?)\)`)

// supersededUpdateIDs mirrors Agent.delete_superseded_updates, whose LooseVersion
// import is an alias for packaging.version.Version, not distutils.LooseVersion.
// Rows are ordered by ID, matching QuerySet.first for substring selections.
func supersededUpdateIDs(rows []supersedenceRow) []int64 {
	type groupKey struct {
		kb   string
		null bool
	}
	groups := make(map[groupKey][]supersedenceRow)
	for _, row := range rows {
		key := groupKey{null: row.KB == nil}
		if row.KB != nil {
			key.kb = *row.KB
		}
		groups[key] = append(groups[key], row)
	}
	selected := make(map[int64]bool)
	for _, group := range groups {
		if len(group) < 2 {
			continue
		}
		type candidate struct {
			text    string
			version pep440.Version
		}
		versions := make([]candidate, 0, len(group))
		for _, row := range group {
			if row.Title == nil {
				break
			}
			match := supersedenceVersion.FindStringSubmatch(*row.Title)
			if match == nil {
				break
			}
			text := strings.TrimSpace(match[2])
			version, err := pep440.Parse(text)
			if err != nil {
				break
			}
			versions = append(versions, candidate{text, version})
		}
		if len(versions) != len(group) {
			continue
		}
		sort.SliceStable(versions, func(i, j int) bool { return pep440.Compare(versions[i].version, versions[j].version) < 0 })
		for _, old := range versions[:len(versions)-1] {
			for _, row := range group {
				// This is intentionally a case-sensitive substring search, not
				// equality of parsed versions: Django title__contains behaves so.
				if strings.Contains(*row.Title, old.text) {
					selected[row.ID] = true
					break
				}
			}
		}
	}
	ids := make([]int64, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// pruneSupersededUpdates participates in the caller's transaction. Database
// errors propagate so callbacks can roll back rather than partially prune.
func pruneSupersededUpdates(tx *gorm.DB, agentPK int64) error {
	var rows []supersedenceRow
	if err := tx.Table("winupdate_winupdate").Select("id,kb,title").Where("agent_id = ?", agentPK).Order("id").Find(&rows).Error; err != nil {
		return err
	}
	ids := supersededUpdateIDs(rows)
	if len(ids) == 0 {
		return nil
	}
	return tx.Exec("DELETE FROM winupdate_winupdate WHERE agent_id = ? AND id IN ?", agentPK, ids).Error
}

// PruneSupersededUpdates participates in the caller's transaction. Database
// errors propagate so callers can roll back rather than partially prune.
func PruneSupersededUpdates(tx *gorm.DB, agentPK int64) error {
	return pruneSupersededUpdates(tx, agentPK)
}

// ApproveAgentUpdatesBackground applies effective-policy approvals without a
// request audit actor, matching Celery's empty request_local username.
func ApproveAgentUpdatesBackground(tx *gorm.DB, agentID string) (int64, error) {
	return approveAgentUpdates(tx, agentID, nil)
}
