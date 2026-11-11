package com.tracelink.appsec.watchtower.web.database;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.List;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.mysql.MySQLContainer;

import com.tracelink.appsec.module.advisory.AdvisoryModule;
import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.checkov.CheckovModule;
import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.module.json.JsonModule;
import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.module.regex.RegexModule;
import com.tracelink.appsec.watchtower.core.module.AbstractModule;

/**
 * Runs the packaged core and scanner migrations on disposable local MySQL databases, without
 * starting Spring, scanners, or external integrations. Failsafe runs this at {@code verify}.
 */
public class MysqlMigrationIT {

	private static final String CORE_HISTORY = "flyway_schema_history";
	private static final String CORE_LOCATION = "classpath:db/migration";
	private static final MigrationVersion PRE_ASSISTANT_VERSION = MigrationVersion.fromVersion("059");

	// Read the actual modules' migration metadata without invoking their startup hooks or engines.
	private static List<AbstractModule> modules() {
		return List.of(new EsLintModule(null, null), new PMDModule(null, null),
				new RegexModule(null, null), new JsonModule(null), new CheckovModule(null),
				new BetterleaksModule(null), new AdvisoryModule(null), new com.tracelink.appsec.module.opengrep.OpengrepModule(null),
				new com.tracelink.appsec.module.awssecurity.AwsSecurityModule());
	}

	@BeforeAll
	static void requireDockerWhenConfigured() {
		boolean dockerAvailable = DockerClientFactory.instance().isDockerAvailable();
		String ci = System.getenv("CI");
		boolean required = Boolean.getBoolean("watchtower.mysql.required")
				|| (ci != null && !ci.isBlank() && !"false".equalsIgnoreCase(ci));
		if (required) {
			assertTrue(dockerAvailable,
					"MySQL migration gate requires local Docker; it must not be skipped in CI.");
		}
		Assumptions.assumeTrue(dockerAvailable,
				"Local MySQL migration tests skipped: Docker is unavailable. "
						+ "Use -Dwatchtower.mysql.required=true to require this gate.");
	}

	@Test
	void freshInstallMigratesEveryIndependentHistoryAndEnforcesMysqlIndexLimits() throws Exception {
		try (MySQLContainer mysql = newMysql()) {
			mysql.start();
			Flyway core = coreFlyway(mysql, null);
			assertTrue(core.migrate().migrationsExecuted >= 61);
			verifyHistory(core);
			for (AbstractModule module : modules()) {
				Flyway flyway = moduleFlyway(mysql, module, null);
				assertTrue(flyway.migrate().migrationsExecuted > 0, module.getName());
				verifyHistory(flyway);
			}
			try (Connection connection = core.getConfiguration().getDataSource().getConnection()) {
				assertTrue(scalar(connection, "SELECT VERSION()").startsWith("8.4."));
				assertEquals("utf8mb4", scalar(connection, "SELECT @@character_set_database"));
				assertEquals("InnoDB", scalar(connection,
						"SELECT ENGINE FROM information_schema.TABLES "
								+ "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'rules'"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM repo_scan_settings WHERE settings_id = 1 AND paused = FALSE"));
				assertEquals("1", scalar(connection, "SELECT COUNT(*) FROM rule_review_report_settings"
						+ " WHERE settings_id = 1 AND enabled = TRUE AND weekday = 1"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM application_persistence_locks WHERE lock_name = 'rule-review-reports'"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM application_persistence_locks WHERE lock_name = 'variant-searches'"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM application_persistence_locks WHERE lock_name = 'upstream-sync'"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM application_persistence_locks WHERE lock_name = 'assistant-evaluation'"));
				assertEquals("2", scalar(connection, "SELECT COUNT(*) FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()"
						+ " AND TABLE_NAME = 'aws_security_scan_runs' AND COLUMN_NAME IN ('shared_review', 'start_attempt_at')"));
				assertEquals("1", scalar(connection, "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE()"
						+ " AND TABLE_NAME = 'aws_security_repo_review'"));
				try (Statement statement = connection.createStatement()) {
					SQLException failure = assertThrows(SQLException.class, () -> statement.execute(
							"CREATE TABLE oversized_index_probe (a VARCHAR(255), b VARCHAR(255), "
									+ "c VARCHAR(255), d VARCHAR(255), INDEX too_wide (a, b, c, d)) "
									+ "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"));
					assertEquals(1071, failure.getErrorCode(), "MySQL must enforce the 3072-byte key limit");
				}
			}
		}
	}

	@Test
	void upgradeFromV059PreservesAmbiguousLegacyRulesFindingsAndMetrics() throws Exception {
		try (MySQLContainer mysql = newMysql()) {
			mysql.start();
			Flyway baseline = coreFlyway(mysql, "059");
			assertEquals(59, baseline.migrate().migrationsExecuted);
			assertEquals(PRE_ASSISTANT_VERSION, baseline.info().current().getVersion());
			for (AbstractModule module : modules()) {
				assertEquals(1, moduleFlyway(mysql, module, "001").migrate().migrationsExecuted,
						module.getName());
			}
			new ResourceDatabasePopulator(new ClassPathResource("db/fixtures/v059.sql"))
					.execute(baseline.getConfiguration().getDataSource());

			Flyway upgraded = coreFlyway(mysql, null);
			upgraded.migrate();
			verifyHistory(upgraded);
			for (AbstractModule module : modules()) {
				Flyway flyway = moduleFlyway(mysql, module, null);
				flyway.migrate();
				verifyHistory(flyway);
			}
			try (Connection connection = upgraded.getConfiguration().getDataSource().getConnection()) {
				assertEquals("2", scalar(connection,
						"SELECT COUNT(*) FROM rules WHERE name = 'Legacy shared name'"));
				assertEquals("legacy-owner", scalar(connection,
						"SELECT author FROM rules WHERE rule_id = 9101"));
				assertEquals("legacy-pattern", scalar(connection,
						"SELECT CAST(regex_pattern AS CHAR) FROM regex_rules WHERE rule_id = 9101"));
				assertEquals("0", scalar(connection,
						"SELECT provided FROM regex_rules WHERE rule_id = 9101"));
				assertEquals("net.sourceforge.pmd.lang.rule.xpath.XPathRule", scalar(connection,
						"SELECT rule_class FROM pmd_rules WHERE rule_id = 9102"));
				assertEquals("//SyntheticNode", scalar(connection,
						"SELECT CAST(property_value AS CHAR) FROM pmd_properties WHERE rule_id = 9102"));
				assertEquals("synthetic-create-function", scalar(connection,
						"SELECT CAST(create_function AS CHAR) FROM eslint_rules WHERE rule_id = 9103"));
				assertEquals("Synthetic diagnostic", scalar(connection,
						"SELECT message_value FROM eslint_messages WHERE rule_id = 9103"));
				assertEquals("$.synthetic", scalar(connection,
						"SELECT CAST(query AS CHAR) FROM json_rules WHERE rule_id = 9104"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM checkov_rules WHERE rule_id = 9105 AND provided = TRUE"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM rule_definition WHERE rule_id = 9105 "
								+ "AND checkovtype = 'resource' AND entity = 'synthetic_resource' AND iac = 'terraform'"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM betterleaks_rules WHERE rule_id = 9106 AND provided = TRUE "
								+ "AND betterleaks_id = 'synthetic-detector' AND regex IS NULL AND rule_version IS NULL"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM advisory_rules WHERE rule_id = 9107"));
				assertEquals("2", scalar(connection,
						"SELECT COUNT(*) FROM rule_ruleset WHERE ruleset_id = 9201"));
				assertEquals("2", scalar(connection,
						"SELECT COUNT(*) FROM pull_request_violations WHERE scan_entity_id = 9302"));
				assertEquals("2", scalar(connection,
						"SELECT COUNT(*) FROM pull_request_violations WHERE scan_entity_id = 9302 "
								+ "AND execution_rule_id IS NULL AND rule_module IS NULL AND rule_revision IS NULL "
								+ "AND external_rule_key IS NULL AND rule_origin_key IS NULL AND engine_fingerprint IS NULL "
								+ "AND effective_blocking IS NULL AND final_blocking IS NULL AND new_finding IS NULL AND bypassed IS NULL"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM pull_request_scans WHERE scan_entity_id = 9302 "
								+ "AND commit_hash IS NULL AND scanner_executions_json IS NULL "
								+ "AND execution_snapshot_json IS NULL AND blocked = TRUE"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM upload_violations WHERE scan_entity_id = 9402"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM upload_violations WHERE scan_entity_id = 9402 "
								+ "AND execution_rule_id IS NULL AND rule_module IS NULL AND rule_revision IS NULL "
								+ "AND external_rule_key IS NULL AND rule_origin_key IS NULL AND engine_fingerprint IS NULL "
								+ "AND effective_blocking IS NULL AND final_blocking IS NULL AND new_finding IS NULL"));
				assertEquals("1", scalar(connection,"SELECT COUNT(*) FROM pull_request_bypasses WHERE bypass_id=9501 AND reason_code IS NULL"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM finding_feedback"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM rule_metric_scan"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM assistant_sessions"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM missed_vulnerability_cases"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM rules WHERE definition_version <> 0"));
    for (String table : List.of("rule_definition_versions", "rule_candidates", "rule_evaluation_fixtures",
        "rule_candidate_runs", "rule_candidate_actions", "rule_shadow_observations")) {
      assertEquals("0", scalar(connection, "SELECT COUNT(*) FROM " + table));
    }
    assertEquals("11", scalar(connection,"SELECT COUNT(*) FROM application_persistence_locks"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM assistant_evaluation_runs"));
    // V075: one OpenAI row with no key; an admin adds it in Assistant admin.
    assertEquals("1", scalar(connection,"SELECT COUNT(*) FROM ai_integrations WHERE provider = 'OPENAI' AND api_key IS NULL AND version = 0"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM rules WHERE upstream_hold_since IS NOT NULL"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM upstream_updates"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM variant_searches"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM rule_review_reports"));
    // V076: AI theme names start empty; the fingerprint index fits MySQL's key limit.
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM rule_review_theme_names"));
    // V077: approved knowledge and its audit start empty.
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM assistant_knowledge"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM assistant_knowledge_audit"));
    // V078: advisory finding assessments and first views start empty; the unique key fits MySQL's limit.
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM finding_assessments"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM finding_assessment_views"));
    assertEquals("4", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'finding_assessments' AND index_name = 'uk_finding_assessment'"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'assistant_knowledge' AND index_name = 'idx_knowledge_status'"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'rule_review_theme_names' AND index_name = 'idx_theme_names_fingerprint'"));
    // V079: how a pull request closed; the merge gate window's index fits MySQL's key limit.
    assertEquals("4", scalar(connection,"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'pull_request_container' AND column_name IN ('closed_state','closed_at','merged_commit','scan_pending_at_close') AND is_nullable = 'YES'"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'pull_request_container' AND index_name = 'idx_pr_container_closed'"));
    assertEquals("1", scalar(connection,"SELECT COUNT(*) FROM rule_review_report_settings WHERE enabled=TRUE AND weekday=1"));
    assertEquals("8", scalar(connection,"SELECT COUNT(*) FROM module_settings"));
    assertEquals("0", scalar(connection,"SELECT enabled FROM module_settings WHERE module_name='opengrep'"));
    assertEquals("7", scalar(connection,"SELECT COUNT(*) FROM module_settings WHERE enabled=TRUE"));
    assertEquals("1", scalar(connection,"SELECT COUNT(*) FROM assistant_settings WHERE settings_id=1"));
    // V089: reservations remember which AI feature slice they charged. V090: first sightings of AI opinions, keyed by finding and person.
    assertEquals("1", scalar(connection,"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'assistant_request_reservations' AND column_name = 'feature' AND is_nullable = 'YES'"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM finding_ai_exposure"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'finding_ai_exposure' AND index_name = 'PRIMARY'"));
    // V091: batch triage runs (one per scan) and their items start empty.
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM ai_batch_run"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM ai_batch_item"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'ai_batch_run' AND index_name = 'uk_ai_batch_scan'"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'ai_batch_item' AND index_name = 'PRIMARY'"));
    // V092: alert-route drafts start empty, each route carries a version, and the draft lock exists.
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM alert_route_change_set"));
    assertEquals("1", scalar(connection,"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'alert_routes' AND column_name = 'configuration_version' AND is_nullable = 'NO'"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'alert_route_change_set' AND index_name = 'uq_alert_route_change_set_request'"));
    assertEquals("1", scalar(connection,"SELECT COUNT(*) FROM application_persistence_locks WHERE lock_name = 'alert-route-configuration'"));
    // V093: weekly digests start empty; the ISO-week key is unique so one pod's digest is the only one for a week.
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM ai_digest"));
    assertEquals("1", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'ai_digest' AND index_name = 'uq_ai_digest_schedule'"));
    assertEquals("1", scalar(connection,"SELECT COUNT(*) FROM application_persistence_locks WHERE lock_name = 'home-digest'"));
    // V095-V097: the CWE catalog, the organisation's CWE profile and the gap decisions start empty; rules carry secondary CWEs and a security-relevance flag.
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM cwe_entry"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM cwe_profile_entry"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM cwe_gap_decision"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'rules' AND column_name IN ('secondary_cwes','security_relevance')"));
    assertEquals("1", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cwe_gap_decision' AND index_name = 'idx_cwe_gap_decision_cwe'"));
    // V100: a review may carry the person's focus note: a nullable 500-character column.
    assertEquals("YES:500", scalar(connection,"SELECT CONCAT(is_nullable, ':', character_maximum_length) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'ai_review_run' AND column_name = 'focus'"));
    // V101: Bitbucket webhook management: five new tables, per-scope and per-task unique keys, rotation columns on the integration, and receipt expiry.
    assertEquals("5", scalar(connection,"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN ('bb_webhook_control','bb_webhook_scope','bb_webhook_operation','bb_webhook_task','pr_comment_receipts')"));
    assertEquals("0", scalar(connection,"SELECT (SELECT COUNT(*) FROM bb_webhook_scope) + (SELECT COUNT(*) FROM bb_webhook_operation) + (SELECT COUNT(*) FROM bb_webhook_task) + (SELECT COUNT(*) FROM pr_comment_receipts)"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'bb_webhook_scope' AND index_name = 'uq_bb_webhook_scope' AND non_unique = 0"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'bb_webhook_task' AND index_name = 'uq_bb_webhook_task' AND non_unique = 0"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'bb_cloud_integration_entity' AND column_name IN ('previous_webhook_secret','previous_webhook_secret_until') AND is_nullable = 'YES'"));
    assertEquals("1", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'pr_comment_receipts' AND index_name = 'idx_pr_comment_receipt_expiry'"));
    // V099: AI reviews start empty; a scan's runs, a run's files and points, and expiry are indexed.
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM ai_review_run"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM ai_review_file"));
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM ai_review_item"));
    assertEquals("5", scalar(connection,"SELECT COUNT(DISTINCT index_name) FROM information_schema.statistics WHERE table_schema = DATABASE() AND index_name IN ('idx_ai_review_run_scan','idx_ai_review_run_expiry','idx_ai_review_file_run','idx_ai_review_item_run','PRIMARY') AND table_name IN ('ai_review_run','ai_review_file','ai_review_item')"));
    // V098: drafted rules start empty and are found by their author and by expiry.
    assertEquals("0", scalar(connection,"SELECT COUNT(*) FROM rule_draft"));
    assertEquals("2", scalar(connection,"SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'rule_draft' AND index_name IN ('idx_rule_draft_owner','idx_rule_draft_expiry') AND seq_in_index = 1"));
    assertEquals("legacy rationale", scalar(connection,
						"SELECT reason FROM pull_request_bypasses WHERE bypass_id = 9501"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM pull_request_bypass_findings WHERE bypass_id = 9501 "
								+ "AND rule_name = 'Legacy shared name' AND file_path = 'Example.java'"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM pull_request_bypass_requests WHERE request_id = 9502 "
								+ "AND reason = 'legacy comment rationale' AND status = 'PENDING' "
								+ "AND source = 'PR_COMMENT' AND requester_scm_id = 'synthetic-scm-id' "
								+ "AND pending_key = REPEAT('a', 64)"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM metrics_scan_daily WHERE scan_type = 'PULL_REQUEST' "
								+ "AND bucket_start = 1699920000000 AND scan_count = 1 AND violation_count = 2"));
				assertEquals("2", scalar(connection,
						"SELECT violation_count FROM metrics_violation_daily "
								+ "WHERE scan_type = 'PULL_REQUEST' AND violation_name = 'Legacy shared name'"));
				assertEquals("1", scalar(connection,
						"SELECT COUNT(*) FROM metrics_processed_scan WHERE scan_type = 'PULL_REQUEST' "
								+ "AND scan_id = 9302 AND metric_kind = 'VIOLATION'"));
			}
		}
	}

	private static MySQLContainer newMysql() {
		return new MySQLContainer("mysql:8.4")
				.withDatabaseName("watchtower_migrations")
				.withUsername("watchtower_test")
				.withPassword("local-migration-test")
				.withCommand("--character-set-server=utf8mb4", "--collation-server=utf8mb4_unicode_ci");
	}

	private static Flyway coreFlyway(MySQLContainer mysql, String target) {
		return flyway(mysql, CORE_HISTORY, CORE_LOCATION, target, false);
	}

	private static Flyway moduleFlyway(MySQLContainer mysql, AbstractModule module, String target) {
		return flyway(mysql, module.getSchemaHistoryTable(),
				"classpath:" + module.getMigrationsLocation(), target, true);
	}

	private static Flyway flyway(MySQLContainer mysql, String history, String location,
			String target, boolean baselineOnMigrate) {
		var configuration = Flyway.configure()
				.dataSource(mysql.getJdbcUrl(), mysql.getUsername(), mysql.getPassword())
				.table(history).locations(location).failOnMissingLocations(true)
				.baselineOnMigrate(baselineOnMigrate).baselineVersion("0")
				// Same value as application.yaml's default; V040 needs it to parse.
				.placeholders(java.util.Map.of("metricsZoneOffsetMillis", "0"));
		if (target != null) {
			configuration.target(target);
		}
		return configuration.load();
	}

	private static void verifyHistory(Flyway flyway) {
		assertNotNull(flyway.info().current(), flyway.getConfiguration().getTable());
		assertEquals(0, flyway.info().pending().length, flyway.getConfiguration().getTable());
		assertFalse(flyway.info().current().getState().isFailed());
		flyway.validate();
		assertEquals(0, flyway.migrate().migrationsExecuted, "Re-running migrations must be a no-op");
	}

	private static String scalar(Connection connection, String sql) throws SQLException {
		try (Statement statement = connection.createStatement(); ResultSet result = statement.executeQuery(sql)) {
			assertTrue(result.next(), sql);
			return result.getString(1);
		}
	}
}
