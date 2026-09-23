package httpapi

import (
	"errors"

	"gorm.io/gorm"
)

type agentInheritedPolicy struct {
	ID       int64
	Enforced bool
}

type agentPolicyContext struct {
	ID       int64
	AgentID  string
	Platform string
	Policies []agentInheritedPolicy
}

// Resolve current configuration rather than unpickling Django model instances.
// ponytail: recompute on each request; add invalidated Go-owned caching only if
// measured query load warrants it. Shared Python cache entries remain untouched.
func resolveAgentPolicies(db *gorm.DB, agentID string) (agentPolicyContext, error) {
	var rows []struct {
		ID, SiteID, ClientID                  int64
		AgentID, Platform, MonitoringType     string
		AgentBlock, SiteBlock, ClientBlock    bool
		AgentPolicy, SitePolicy, ClientPolicy *int64
	}
	err := db.Table("agents_agent a").
		Joins("JOIN clients_site s ON s.id=a.site_id JOIN clients_client c ON c.id=s.client_id").
		Select(`a.id,a.agent_id,a.plat AS platform,a.monitoring_type,s.id AS site_id,c.id AS client_id,
 a.block_policy_inheritance AS agent_block,s.block_policy_inheritance AS site_block,c.block_policy_inheritance AS client_block,
 a.policy_id AS agent_policy,
 CASE a.monitoring_type WHEN 'server' THEN s.server_policy_id WHEN 'workstation' THEN s.workstation_policy_id END AS site_policy,
 CASE a.monitoring_type WHEN 'server' THEN c.server_policy_id WHEN 'workstation' THEN c.workstation_policy_id END AS client_policy`).
		Where("a.agent_id = ?", agentID).Find(&rows).Error
	if err != nil {
		return agentPolicyContext{}, err
	}
	if len(rows) == 0 {
		return agentPolicyContext{}, agentNotFound()
	}
	a := rows[0]
	var settings []struct{ ServerPolicyID, WorkstationPolicyID *int64 }
	if err := db.Table("core_coresettings").Select("server_policy_id,workstation_policy_id").Order("id").Limit(1).Find(&settings).Error; err != nil {
		return agentPolicyContext{}, err
	}
	if len(settings) == 0 {
		return agentPolicyContext{}, errors.New("CoreSettings not found")
	}
	var defaultPolicy *int64
	switch a.MonitoringType {
	case "server":
		defaultPolicy = settings[0].ServerPolicyID
	case "workstation":
		defaultPolicy = settings[0].WorkstationPolicyID
	}
	ids := []int64{}
	for _, candidate := range []struct {
		id      *int64
		blocked bool
	}{
		{a.AgentPolicy, false},
		{a.SitePolicy, a.AgentBlock},
		{a.ClientPolicy, a.AgentBlock || a.SiteBlock},
		{defaultPolicy, a.AgentBlock || a.SiteBlock || a.ClientBlock},
	} {
		if candidate.id != nil && !candidate.blocked {
			ids = append(ids, *candidate.id)
		}
	}
	out := agentPolicyContext{ID: a.ID, AgentID: a.AgentID, Platform: a.Platform, Policies: []agentInheritedPolicy{}}
	if len(ids) == 0 {
		return out, nil
	}
	var policies []agentInheritedPolicy
	err = db.Table("automation_policy p").Select("p.id,p.enforced").Where("p.id IN ? AND p.active", ids).
		Where("NOT EXISTS (SELECT 1 FROM automation_policy_excluded_agents e WHERE e.policy_id=p.id AND e.agent_id=?)", a.ID).
		Where("NOT EXISTS (SELECT 1 FROM automation_policy_excluded_sites e WHERE e.policy_id=p.id AND e.site_id=?)", a.SiteID).
		Where("NOT EXISTS (SELECT 1 FROM automation_policy_excluded_clients e WHERE e.policy_id=p.id AND e.client_id=?)", a.ClientID).
		Find(&policies).Error
	if err != nil {
		return agentPolicyContext{}, err
	}
	available := make(map[int64]agentInheritedPolicy, len(policies))
	for _, policy := range policies {
		available[policy.ID] = policy
	}
	for _, id := range ids {
		if policy, ok := available[id]; ok {
			out.Policies = append(out.Policies, policy)
			delete(available, id)
		}
	}
	return out, nil
}
