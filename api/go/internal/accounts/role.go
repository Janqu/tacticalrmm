package accounts

import "time"

// Role maps accounts.Role, including its audit fields and permission flags.
type Role struct {
	ID                          int64      `gorm:"primaryKey" json:"id"`
	Name                        string     `json:"name"`
	CreatedBy                   *string    `json:"created_by"`
	CreatedTime                 *time.Time `json:"created_time"`
	ModifiedBy                  *string    `json:"modified_by"`
	ModifiedTime                *time.Time `json:"modified_time"`
	IsSuperuser                 bool       `gorm:"column:is_superuser" json:"is_superuser"`
	CanListAgents               bool       `gorm:"column:can_list_agents" json:"can_list_agents"`
	CanUseMesh                  bool       `gorm:"column:can_use_mesh" json:"can_use_mesh"`
	CanUninstallAgents          bool       `gorm:"column:can_uninstall_agents" json:"can_uninstall_agents"`
	CanUpdateAgents             bool       `gorm:"column:can_update_agents" json:"can_update_agents"`
	CanEditAgent                bool       `gorm:"column:can_edit_agent" json:"can_edit_agent"`
	CanManageProcs              bool       `gorm:"column:can_manage_procs" json:"can_manage_procs"`
	CanViewEventlogs            bool       `gorm:"column:can_view_eventlogs" json:"can_view_eventlogs"`
	CanSendCmd                  bool       `gorm:"column:can_send_cmd" json:"can_send_cmd"`
	CanRebootAgents             bool       `gorm:"column:can_reboot_agents" json:"can_reboot_agents"`
	CanInstallAgents            bool       `gorm:"column:can_install_agents" json:"can_install_agents"`
	CanRunScripts               bool       `gorm:"column:can_run_scripts" json:"can_run_scripts"`
	CanRunBulk                  bool       `gorm:"column:can_run_bulk" json:"can_run_bulk"`
	CanRecoverAgents            bool       `gorm:"column:can_recover_agents" json:"can_recover_agents"`
	CanListAgentHistory         bool       `gorm:"column:can_list_agent_history" json:"can_list_agent_history"`
	CanSendWol                  bool       `gorm:"column:can_send_wol" json:"can_send_wol"`
	CanUseRegistry              bool       `gorm:"column:can_use_registry" json:"can_use_registry"`
	CanUseTerminal              bool       `gorm:"column:can_use_terminal" json:"can_use_terminal"`
	CanListNotes                bool       `gorm:"column:can_list_notes" json:"can_list_notes"`
	CanManageNotes              bool       `gorm:"column:can_manage_notes" json:"can_manage_notes"`
	CanViewCoreSettings         bool       `gorm:"column:can_view_core_settings" json:"can_view_core_settings"`
	CanEditCoreSettings         bool       `gorm:"column:can_edit_core_settings" json:"can_edit_core_settings"`
	CanDoServerMaint            bool       `gorm:"column:can_do_server_maint" json:"can_do_server_maint"`
	CanCodeSign                 bool       `gorm:"column:can_code_sign" json:"can_code_sign"`
	CanRunUrlactions            bool       `gorm:"column:can_run_urlactions" json:"can_run_urlactions"`
	CanViewCustomfields         bool       `gorm:"column:can_view_customfields" json:"can_view_customfields"`
	CanManageCustomfields       bool       `gorm:"column:can_manage_customfields" json:"can_manage_customfields"`
	CanRunServerScripts         bool       `gorm:"column:can_run_server_scripts" json:"can_run_server_scripts"`
	CanUseWebterm               bool       `gorm:"column:can_use_webterm" json:"can_use_webterm"`
	CanViewGlobalKeystore       bool       `gorm:"column:can_view_global_keystore" json:"can_view_global_keystore"`
	CanEditGlobalKeystore       bool       `gorm:"column:can_edit_global_keystore" json:"can_edit_global_keystore"`
	CanViewSchedules            bool       `gorm:"column:can_view_schedules" json:"can_view_schedules"`
	CanManageSchedules          bool       `gorm:"column:can_manage_schedules" json:"can_manage_schedules"`
	CanListChecks               bool       `gorm:"column:can_list_checks" json:"can_list_checks"`
	CanManageChecks             bool       `gorm:"column:can_manage_checks" json:"can_manage_checks"`
	CanRunChecks                bool       `gorm:"column:can_run_checks" json:"can_run_checks"`
	CanListClients              bool       `gorm:"column:can_list_clients" json:"can_list_clients"`
	CanManageClients            bool       `gorm:"column:can_manage_clients" json:"can_manage_clients"`
	CanListSites                bool       `gorm:"column:can_list_sites" json:"can_list_sites"`
	CanManageSites              bool       `gorm:"column:can_manage_sites" json:"can_manage_sites"`
	CanListDeployments          bool       `gorm:"column:can_list_deployments" json:"can_list_deployments"`
	CanManageDeployments        bool       `gorm:"column:can_manage_deployments" json:"can_manage_deployments"`
	CanListAutomationPolicies   bool       `gorm:"column:can_list_automation_policies" json:"can_list_automation_policies"`
	CanManageAutomationPolicies bool       `gorm:"column:can_manage_automation_policies" json:"can_manage_automation_policies"`
	CanListAutotasks            bool       `gorm:"column:can_list_autotasks" json:"can_list_autotasks"`
	CanManageAutotasks          bool       `gorm:"column:can_manage_autotasks" json:"can_manage_autotasks"`
	CanRunAutotasks             bool       `gorm:"column:can_run_autotasks" json:"can_run_autotasks"`
	CanViewAuditlogs            bool       `gorm:"column:can_view_auditlogs" json:"can_view_auditlogs"`
	CanListPendingactions       bool       `gorm:"column:can_list_pendingactions" json:"can_list_pendingactions"`
	CanManagePendingactions     bool       `gorm:"column:can_manage_pendingactions" json:"can_manage_pendingactions"`
	CanViewDebuglogs            bool       `gorm:"column:can_view_debuglogs" json:"can_view_debuglogs"`
	CanListScripts              bool       `gorm:"column:can_list_scripts" json:"can_list_scripts"`
	CanManageScripts            bool       `gorm:"column:can_manage_scripts" json:"can_manage_scripts"`
	CanListAlerts               bool       `gorm:"column:can_list_alerts" json:"can_list_alerts"`
	CanManageAlerts             bool       `gorm:"column:can_manage_alerts" json:"can_manage_alerts"`
	CanListAlerttemplates       bool       `gorm:"column:can_list_alerttemplates" json:"can_list_alerttemplates"`
	CanManageAlerttemplates     bool       `gorm:"column:can_manage_alerttemplates" json:"can_manage_alerttemplates"`
	CanManageWinsvcs            bool       `gorm:"column:can_manage_winsvcs" json:"can_manage_winsvcs"`
	CanListSoftware             bool       `gorm:"column:can_list_software" json:"can_list_software"`
	CanManageSoftware           bool       `gorm:"column:can_manage_software" json:"can_manage_software"`
	CanManageWinupdates         bool       `gorm:"column:can_manage_winupdates" json:"can_manage_winupdates"`
	CanListAccounts             bool       `gorm:"column:can_list_accounts" json:"can_list_accounts"`
	CanManageAccounts           bool       `gorm:"column:can_manage_accounts" json:"can_manage_accounts"`
	CanListRoles                bool       `gorm:"column:can_list_roles" json:"can_list_roles"`
	CanManageRoles              bool       `gorm:"column:can_manage_roles" json:"can_manage_roles"`
	CanListApiKeys              bool       `gorm:"column:can_list_api_keys" json:"can_list_api_keys"`
	CanManageApiKeys            bool       `gorm:"column:can_manage_api_keys" json:"can_manage_api_keys"`
	CanViewReports              bool       `gorm:"column:can_view_reports" json:"can_view_reports"`
	CanManageReports            bool       `gorm:"column:can_manage_reports" json:"can_manage_reports"`
}

func (Role) TableName() string { return "accounts_role" }

func (r *Role) Allows(permission string) bool {
	switch permission {
	case "can_list_agents":
		return r.CanListAgents
	case "can_use_mesh":
		return r.CanUseMesh
	case "can_uninstall_agents":
		return r.CanUninstallAgents
	case "can_update_agents":
		return r.CanUpdateAgents
	case "can_edit_agent":
		return r.CanEditAgent
	case "can_manage_procs":
		return r.CanManageProcs
	case "can_view_eventlogs":
		return r.CanViewEventlogs
	case "can_send_cmd":
		return r.CanSendCmd
	case "can_reboot_agents":
		return r.CanRebootAgents
	case "can_install_agents":
		return r.CanInstallAgents
	case "can_run_scripts":
		return r.CanRunScripts
	case "can_run_bulk":
		return r.CanRunBulk
	case "can_recover_agents":
		return r.CanRecoverAgents
	case "can_list_agent_history":
		return r.CanListAgentHistory
	case "can_send_wol":
		return r.CanSendWol
	case "can_use_registry":
		return r.CanUseRegistry
	case "can_use_terminal":
		return r.CanUseTerminal
	case "can_list_notes":
		return r.CanListNotes
	case "can_manage_notes":
		return r.CanManageNotes
	case "can_view_core_settings":
		return r.CanViewCoreSettings
	case "can_edit_core_settings":
		return r.CanEditCoreSettings
	case "can_do_server_maint":
		return r.CanDoServerMaint
	case "can_code_sign":
		return r.CanCodeSign
	case "can_run_urlactions":
		return r.CanRunUrlactions
	case "can_view_customfields":
		return r.CanViewCustomfields
	case "can_manage_customfields":
		return r.CanManageCustomfields
	case "can_run_server_scripts":
		return r.CanRunServerScripts
	case "can_use_webterm":
		return r.CanUseWebterm
	case "can_view_global_keystore":
		return r.CanViewGlobalKeystore
	case "can_edit_global_keystore":
		return r.CanEditGlobalKeystore
	case "can_view_schedules":
		return r.CanViewSchedules
	case "can_manage_schedules":
		return r.CanManageSchedules
	case "can_list_checks":
		return r.CanListChecks
	case "can_manage_checks":
		return r.CanManageChecks
	case "can_run_checks":
		return r.CanRunChecks
	case "can_list_clients":
		return r.CanListClients
	case "can_manage_clients":
		return r.CanManageClients
	case "can_list_sites":
		return r.CanListSites
	case "can_manage_sites":
		return r.CanManageSites
	case "can_list_deployments":
		return r.CanListDeployments
	case "can_manage_deployments":
		return r.CanManageDeployments
	case "can_list_automation_policies":
		return r.CanListAutomationPolicies
	case "can_manage_automation_policies":
		return r.CanManageAutomationPolicies
	case "can_list_autotasks":
		return r.CanListAutotasks
	case "can_manage_autotasks":
		return r.CanManageAutotasks
	case "can_run_autotasks":
		return r.CanRunAutotasks
	case "can_view_auditlogs":
		return r.CanViewAuditlogs
	case "can_list_pendingactions":
		return r.CanListPendingactions
	case "can_manage_pendingactions":
		return r.CanManagePendingactions
	case "can_view_debuglogs":
		return r.CanViewDebuglogs
	case "can_list_scripts":
		return r.CanListScripts
	case "can_manage_scripts":
		return r.CanManageScripts
	case "can_list_alerts":
		return r.CanListAlerts
	case "can_manage_alerts":
		return r.CanManageAlerts
	case "can_list_alerttemplates":
		return r.CanListAlerttemplates
	case "can_manage_alerttemplates":
		return r.CanManageAlerttemplates
	case "can_manage_winsvcs":
		return r.CanManageWinsvcs
	case "can_list_software":
		return r.CanListSoftware
	case "can_manage_software":
		return r.CanManageSoftware
	case "can_manage_winupdates":
		return r.CanManageWinupdates
	case "can_list_accounts":
		return r.CanListAccounts
	case "can_manage_accounts":
		return r.CanManageAccounts
	case "can_list_roles":
		return r.CanListRoles
	case "can_manage_roles":
		return r.CanManageRoles
	case "can_list_api_keys":
		return r.CanListApiKeys
	case "can_manage_api_keys":
		return r.CanManageApiKeys
	case "can_view_reports":
		return r.CanViewReports
	case "can_manage_reports":
		return r.CanManageReports
	default:
		return false
	}
}
