package com.tracelink.appsec.watchtower.core.auth.model;

/**
 * Core Privileges are owned and used by the Watchtower Core system
 *
 * @author csmith
 */
public enum CorePrivilege {
 MODULE_SETTINGS_VIEW(CorePrivilege.MODULE_SETTINGS_VIEW_NAME,CorePrivilege.CONFIG_CATEGORY,"See which scanner modules are on, their status and file types, without changing them."),
 MODULE_SETTINGS(CorePrivilege.MODULE_SETTINGS_NAME,CorePrivilege.CONFIG_CATEGORY,"Enable or disable execution and designers without deleting rules/history."),
 FINDING_FEEDBACK(CorePrivilege.FINDING_FEEDBACK_NAME, CorePrivilege.SCAN_CATEGORY, "Review individual findings independently of enforcement."),
 ASSISTANT_USE(CorePrivilege.ASSISTANT_USE_NAME, CorePrivilege.RULES_CATEGORY, "Use read-only assistance and own history."),
 ASSISTANT_SOURCE(CorePrivilege.ASSISTANT_SOURCE_NAME, CorePrivilege.RULES_CATEGORY, "Read pinned repository source through bounded assistant tools."),
 ASSISTANT_AUDIT(CorePrivilege.ASSISTANT_AUDIT_NAME, CorePrivilege.ADMIN_CATEGORY, "Read assistant audit metadata and expiring transcripts."),
 ASSISTANT_ADMIN(CorePrivilege.ASSISTANT_ADMIN_NAME, CorePrivilege.ADMIN_CATEGORY, "Configure assistant models, retention and limits."),


	/* Core Admin */
	USER_VIEW(CorePrivilege.USER_VIEW_NAME, CorePrivilege.ADMIN_CATEGORY,
			"User may view other user accounts."),
	USER_MODIFY(CorePrivilege.USER_MODIFY_NAME, CorePrivilege.ADMIN_CATEGORY,
			"User may modify any other user's account."),
	ROLE_VIEW(CorePrivilege.ROLE_VIEW_NAME, CorePrivilege.ADMIN_CATEGORY,
			"User may view all roles in the system"),
	ROLE_MODIFY(CorePrivilege.ROLE_MODIFY_NAME, CorePrivilege.ADMIN_CATEGORY,
			"User may modify any role in the system"),
	ENCRYPTION_VIEW(CorePrivilege.ENCRYPTION_VIEW_NAME, CorePrivilege.ADMIN_CATEGORY,
			"User may view the current state of database row encryption and key management."),
	ENCRYPTION_MODIFY(CorePrivilege.ENCRYPTION_MODIFY_NAME, CorePrivilege.ADMIN_CATEGORY,
			"User may modify the state of database row encryption and key management."),
	LOGGING_VIEW(CorePrivilege.LOGGING_VIEW_NAME, CorePrivilege.ADMIN_CATEGORY,
			"User may view the most recent logs in the system"),
	LOGGING_MODIFY(CorePrivilege.LOGGING_MODIFY_NAME, CorePrivilege.ADMIN_CATEGORY,
			"User may modify the current logging level."),
	LOGGING_DOWNLOAD(CorePrivilege.LOGGING_DOWNLOAD_NAME, CorePrivilege.ADMIN_CATEGORY,
			"User may download all system logs from the last few days."),

	/* Core Config */
	API_SETTINGS_VIEW(CorePrivilege.API_SETTINGS_VIEW_NAME, CorePrivilege.CONFIG_CATEGORY,
			"User may view and test the current API Integration Settings (minus any credentials), as well as see the webhook endpoint for APIs."),
	API_SETTINGS_MODIFY(CorePrivilege.API_SETTINGS_MODIFY_NAME, CorePrivilege.CONFIG_CATEGORY,
			"User may modify the current API Settings."),
	REPOSITORY_SETTINGS_VIEW(CorePrivilege.REPO_SETTINGS_VIEW_NAME, CorePrivilege.CONFIG_CATEGORY,
			"User may view the current assignment of rulesets to known repositories in each SCM."),
	REPOSITORY_SETTINGS_MODIFY(CorePrivilege.REPO_SETTINGS_MODIFY_NAME,
			CorePrivilege.CONFIG_CATEGORY,
			"User may modify the current assignment of rulesets to known repositories in each SCM."),
	ALERT_SETTINGS_VIEW(CorePrivilege.ALERT_SETTINGS_VIEW_NAME, CorePrivilege.CONFIG_CATEGORY,
			"User may view alert channels (with masked webhook URLs), routes and recent alerts."),
	ALERT_SETTINGS_MODIFY(CorePrivilege.ALERT_SETTINGS_MODIFY_NAME,
			CorePrivilege.CONFIG_CATEGORY,
			"User may add, change and test alert channels and routes."),
	PR_SETTINGS_VIEW(CorePrivilege.PR_SETTINGS_VIEW_NAME, CorePrivilege.CONFIG_CATEGORY,
			"User may view the current PR Settings (Pull Request Data Sync frequency and full-source download threshold)."),
	PR_SETTINGS_MODIFY(CorePrivilege.PR_SETTINGS_MODIFY_NAME,
			CorePrivilege.CONFIG_CATEGORY,
			"User may modify the PR Settings (Pull Request Data Sync frequency and full-source download threshold)."),

	/* Core Rules */
	RULE_MODIFY(CorePrivilege.RULE_MODIFY_NAME, CorePrivilege.RULES_CATEGORY,
			"User may modify or delete an existing rule. Individual Scanners may implement additional privileges."),
	RULE_DESIGNER(CorePrivilege.RULE_DESIGNER_NAME, CorePrivilege.RULES_CATEGORY,
			"User may access the Rule Designer. Individual Scanners may implement additional privileges."),
	RULESETS_VIEW(CorePrivilege.RULESETS_VIEW_NAME, CorePrivilege.RULES_CATEGORY,
			"User may view all rulesets in the system and the rules in the rulesets."),
	RULESETS_MODIFY(CorePrivilege.RULESETS_MODIFY_NAME, CorePrivilege.RULES_CATEGORY,
			"User may modify any ruleset in the system."),
	RULESETS_IMPEX(CorePrivilege.RULESETS_IMPEX_NAME, CorePrivilege.RULES_CATEGORY,
			"User may import and export rulesets. Caution: Importing rulesets can overwrite existing rules, modifying system accuracy"),

	/* Core Scan */
	SCAN_DASHBOARDS(CorePrivilege.SCAN_DASHBOARDS_NAME, CorePrivilege.SCAN_CATEGORY,
			"User may view all Dashboards for Scans."),
	SCAN_SUBMIT(CorePrivilege.SCAN_SUBMIT_NAME, CorePrivilege.SCAN_CATEGORY,
			"User may Submit Scans using the UI and view the most recent results."),
	SCAN_ADMIN(CorePrivilege.SCAN_ADMIN_NAME, CorePrivilege.SCAN_CATEGORY,
			"User may pause, quiesce, and resume scanners."),
	SCAN_RESULTS(CorePrivilege.SCAN_RESULTS_NAME, CorePrivilege.SCAN_CATEGORY,
			"User may view all scan results for all time."),
	SCAN_MCR_MODIFY(CorePrivilege.SCAN_MCR_MODIFY_NAME, CorePrivilege.SCAN_CATEGORY,
			"User may modify the MCR status of a Pull Request Scan."),
	PR_SCAN_BYPASS(CorePrivilege.PR_SCAN_BYPASS_NAME, CorePrivilege.SCAN_CATEGORY,
			"User may bypass Watchtower's blocking of one pull request, with a reason, and revoke"
					+ " a bypass. Every bypass is commented on the pull request and alerted.");

	private static final String ADMIN_CATEGORY = "Admin";
	private static final String CONFIG_CATEGORY = "Configuration";
	private static final String RULES_CATEGORY = "Rules";
	private static final String SCAN_CATEGORY = "Scan";


	public static final String FINDING_FEEDBACK_NAME = "Finding Feedback";
 public static final String ASSISTANT_USE_NAME = "Assistant Use";
 public static final String ASSISTANT_SOURCE_NAME = "Assistant Source Read";
 public static final String ASSISTANT_AUDIT_NAME = "Assistant Audit";
 public static final String ASSISTANT_ADMIN_NAME = "Assistant Admin";
 /* Core Admin Names */
	public static final String USER_VIEW_NAME = "User Management View";
	public static final String USER_MODIFY_NAME = "User Management Modify";
	public static final String ROLE_VIEW_NAME = "Role Management View";
	public static final String ROLE_MODIFY_NAME = "Role Management Modify";
	public static final String ENCRYPTION_VIEW_NAME = "Encryption Management View";
	public static final String ENCRYPTION_MODIFY_NAME = "Encryption Management Modify";
	public static final String LOGGING_VIEW_NAME = "Logging View";
	public static final String LOGGING_MODIFY_NAME = "Logging Modify";
	public static final String LOGGING_DOWNLOAD_NAME = "Logging Download";

	/* Core Config Names */
 public static final String MODULE_SETTINGS_NAME="Module Settings Modify";
 public static final String MODULE_SETTINGS_VIEW_NAME="Module Settings View";
	public static final String API_SETTINGS_VIEW_NAME = "API Settings View";
	public static final String API_SETTINGS_MODIFY_NAME = "API Settings Modify";
	public static final String REPO_SETTINGS_VIEW_NAME = "Repository Settings View";
	public static final String REPO_SETTINGS_MODIFY_NAME = "Repository Settings Modify";
	public static final String ALERT_SETTINGS_VIEW_NAME = "Alert Settings View";
	public static final String ALERT_SETTINGS_MODIFY_NAME = "Alert Settings Modify";
	public static final String PR_SETTINGS_VIEW_NAME = "PR Settings View";
	public static final String PR_SETTINGS_MODIFY_NAME = "PR Settings Modify";

	/* Core Rules Names */
	public static final String RULE_MODIFY_NAME = "Rule Modify";
	public static final String RULE_DESIGNER_NAME = "Rule Designer";
	public static final String RULESETS_VIEW_NAME = "Ruleset View";
	public static final String RULESETS_MODIFY_NAME = "Ruleset Modify";
	public static final String RULESETS_IMPEX_NAME = "Ruleset Import/Export";


	/* Core Scan Names */
	public static final String SCAN_DASHBOARDS_NAME = "Scan Dashboard View";
	public static final String SCAN_SUBMIT_NAME = "Scan Submit";
	public static final String SCAN_ADMIN_NAME = "Scan Admin";
	public static final String SCAN_RESULTS_NAME = "Scan Results View";
	public static final String SCAN_MCR_MODIFY_NAME = "Scan MCR Modify";
	public static final String PR_SCAN_BYPASS_NAME = "PR Scan Bypass";

	/* API Integration Scan */
	public static final String INTEGRATION_SCAN_SUBMIT = "Integration Scan Submit";

	private final String name;
	private final String category;
	private final String desc;

	CorePrivilege(String name, String category, String desc) {
		this.name = name;
		this.category = category;
		this.desc = desc;
	}

	public String getPrivilegeName() {
		return name;
	}

	public String getCategory() {
		return category;
	}

	public String getDescription() {
		return desc;
	}

}
