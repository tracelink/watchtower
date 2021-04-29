package com.tracelink.appsec.watchtower.core.auth.model;

/**
 * Core Privileges are owned and used by the Watchtower Core system
 * 
 * @author csmith
 *
 */
public enum CorePrivilege {

	/* Core Admin */
	DB_ACCESS(CorePrivilege.DB_ACCESS_NAME, CorePrivilege.ADMIN_CATEGORY,
			"User may access the DB console in order to make SQL queries against the database (Requires DB Credentials)."),
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
			"User may view and test the current SCM API Settings (minus any credentials), as well as see the webhook endpoint for APIs."),
	API_SETTINGS_MODIFY(CorePrivilege.API_SETTINGS_MODIFY_NAME, CorePrivilege.CONFIG_CATEGORY,
			"User may modify the current API Settings."),
	REPOSITORY_SETTINGS_VIEW(CorePrivilege.REPO_SETTINGS_VIEW_NAME, CorePrivilege.CONFIG_CATEGORY,
			"User may view the current assignment of rulesets to known repositories in each SCM."),
	REPOSITORY_SETTINGS_MODIFY(CorePrivilege.REPO_SETTINGS_MODIFY_NAME,
			CorePrivilege.CONFIG_CATEGORY,
			"User may modify the current assignment of rulesets to known repositories in each SCM."),

	/* Core Rules */
	RULESET_MGMT_MODIFY(CorePrivilege.RULESET_MGMT_MODIFY_NAME, CorePrivilege.RULES_CATEGORY,
			"User may access and change data about Rulesets including Hierarchy, default rulesets, and blocking."),
	RULE_MODIFY(CorePrivilege.RULE_MODIFY_NAME, CorePrivilege.RULES_CATEGORY,
			"User may modify or delete an existing rule. Individual Scanners may implement additional privileges."),
	RULE_DESIGNER(CorePrivilege.RULE_DESIGNER_NAME, CorePrivilege.RULES_CATEGORY,
			"User may access the Rule Designer. Individual Scanners may implement additional privileges."),
	RULESETS_VIEW(CorePrivilege.RULESETS_VIEW_NAME, CorePrivilege.RULES_CATEGORY,
			"User may view all rulesets in the system and the rules in the rulesets as well as export any ruleset."),
	RULESETS_MODIFY(CorePrivilege.RULESETS_MODIFY_NAME, CorePrivilege.RULES_CATEGORY,
			"User may modify any ruleset in the system."),

	/* Core Scan */
	SCAN_DASHBOARDS(CorePrivilege.SCAN_DASHBOARDS_NAME, CorePrivilege.SCAN_CATEGORY,
			"User may view all Dashboards for Scans."),
	SCAN_SUBMIT(CorePrivilege.SCAN_SUBMIT_NAME, CorePrivilege.SCAN_CATEGORY,
			"User may Submit Scans using the UI and view the most recent results."),
	SCAN_ADMIN(CorePrivilege.SCAN_ADMIN_NAME, CorePrivilege.SCAN_CATEGORY,
			"User may pause, quiesce, and resume scanners."),
	SCAN_RESULTS(CorePrivilege.SCAN_RESULTS_NAME, CorePrivilege.SCAN_CATEGORY,
			"User may view all scan results for all time.");

	private static final String ADMIN_CATEGORY = "Admin";
	private static final String CONFIG_CATEGORY = "Configuration";
	private static final String RULES_CATEGORY = "Rules";
	private static final String SCAN_CATEGORY = "Scan";


	/* Core Admin Names */
	public static final String DB_ACCESS_NAME = "Database Access";
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
	public static final String API_SETTINGS_VIEW_NAME = "SCM API Settings View";
	public static final String API_SETTINGS_MODIFY_NAME = "API Settings Modify";
	public static final String REPO_SETTINGS_VIEW_NAME = "Repository Settings View";
	public static final String REPO_SETTINGS_MODIFY_NAME = "Repository Settings Modify";

	/* Core Rules Names */
	public static final String RULESET_MGMT_MODIFY_NAME = "Ruleset Management Access";
	public static final String RULE_MODIFY_NAME = "Rule Modify";
	public static final String RULE_DESIGNER_NAME = "Rule Designer";
	public static final String RULESETS_VIEW_NAME = "Ruleset View";
	public static final String RULESETS_MODIFY_NAME = "Ruleset Modify";

	/* Core Scan Names */
	public static final String SCAN_DASHBOARDS_NAME = "Scan Dashboard View";
	public static final String SCAN_SUBMIT_NAME = "Scan Submit";
	public static final String SCAN_ADMIN_NAME = "Scan Admin";
	public static final String SCAN_RESULTS_NAME = "Scan Results View";

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
