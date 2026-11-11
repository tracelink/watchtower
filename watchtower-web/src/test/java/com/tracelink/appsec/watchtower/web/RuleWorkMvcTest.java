package com.tracelink.appsec.watchtower.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import jakarta.persistence.EntityManager;
import jakarta.persistence.EntityManagerFactory;

import org.hibernate.SessionFactory;
import org.hibernate.stat.Statistics;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.watchtower.core.persistence.FindingFeedbackEntity;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.persistence.RuleCandidateEntity;
import com.tracelink.appsec.watchtower.core.persistence.RuleMetricScanEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleRepository;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.PlanFrequency;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanPlanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanPlanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/** The rule work overview: five queues from existing records, authorized, filtered and paged. */
@SpringBootTest(properties = {"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false",
		"spring.datasource.url=jdbc:h2:mem:uat-work;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
		"spring.jpa.properties.hibernate.generate_statistics=true"})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Transactional
class RuleWorkMvcTest {
	private static final String PREFIX = "WorkFixture ";

	@MockitoBean
	com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
	@Autowired
	MockMvc mvc;
	@Autowired
	RepoScanRepository repoScans;
	@Autowired
	RepoScanPlanRepository repoScanPlans;
	@Autowired
	RepositoryRepository repositories;
	@Autowired
	RuleRepository rules;
	@Autowired
	LedgerRepository records;
	@Autowired
	com.tracelink.appsec.watchtower.core.rule.RuleRevisionBackfill backfill;
	@Autowired
	EntityManager entities;
	@Autowired
	EntityManagerFactory entityManagerFactory;
	@Autowired
	com.tracelink.appsec.watchtower.core.rule.RuleService ruleService;

	private final UserRequestPostProcessor viewer =
			user("viewer").authorities(() -> "Ruleset View", () -> "Scan Results View");
	private final UserRequestPostProcessor reader = user("reader").authorities(() -> "Ruleset View");

	private long noisy;
	private long unreviewed;
	private long overdue;
	private long drafted;
	private long unreviewedScan;

	@BeforeEach
	void seed() {
		long now = System.currentTimeMillis();
		noisy = save("Noisy <script>", null, null).getId();
		unreviewed = save("Unreviewed", null, null).getId();
		overdue = save("Overdue", "alice", LocalDate.now(ZoneOffset.UTC).minusDays(1)).getId();
		drafted = save("Drafted", "bob", null).getId();

		// 8 of 10 reviewed matches are false positives: an investigation, not a review request.
		metric(noisy, "pull_request", 1L, 10, now);
		for (int i = 0; i < 10; i++) {
			feedback(noisy, "pull_request", 1L, i < 8 ? "FALSE_POSITIVE" : "TRUE_POSITIVE", now);
		}
		// 42 matches with nothing reviewed and one occurrence marked Unknown.
		unreviewedScan = repoScan();
		metric(unreviewed, "repository", unreviewedScan, 42, now);
		feedback(unreviewed, "repository", unreviewedScan, "UNKNOWN", now);

		RuleEntity draftRule = rules.findById(drafted).orElseThrow();
		records.insert(new RuleCandidateEntity(UUID.randomUUID().toString(), drafted,
				revision(draftRule), "a".repeat(64), "b".repeat(64), "{}", "DRAFT",
				"Narrow the pattern", "bob", null, now, now, 0L));
		records.flush();
	}

	@Test
	void reviewQueueListsRulesWithMatchesButTooFewReviewedFindings() throws Exception {
		mvc.perform(get("/rules/work").param("search", PREFIX).with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("WorkFixture Unreviewed")))
				.andExpect(content().string(containsString("42 matches")))
				.andExpect(content().string(containsString("1 marked Unknown")))
				// Tab labels and counts render (a SpEL map[var] lookup once left them blank).
				.andExpect(content().string(containsString("Findings to review")))
				.andExpect(content().string(containsString("Setup gaps")))
				.andExpect(content().string(containsString("/reposcan/report/" + unreviewedScan + "?reviewSearch=WorkFixture%20Unreviewed")))
				.andExpect(content().string(not(containsString("WorkFixture Noisy"))));
	}

	@Test
	void investigationQueueShowsReviewedFalsePositiveEvidence() throws Exception {
		mvc.perform(get("/rules/work").param("queue", "investigate").param("search", PREFIX).with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("WorkFixture Noisy &lt;script&gt;")))
				.andExpect(content().string(containsString("8 of 10 reviewed findings are false positives")))
				.andExpect(content().string(containsString("/rules/" + noisy + "/health?days=30")))
				.andExpect(content().string(not(containsString("WorkFixture Unreviewed"))));
	}

	@Test
	void reviewsQueueShowsOverdueOwnedRulesAndOwnerFilter() throws Exception {
		mvc.perform(get("/rules/work").param("queue", "reviews").param("search", PREFIX).with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("WorkFixture Overdue")))
				.andExpect(content().string(containsString("Review overdue since")))
				.andExpect(content().string(containsString("/rules/" + overdue + "/reviews?state=pending")));
		mvc.perform(get("/rules/work").param("queue", "reviews").param("search", PREFIX)
				.param("owner", "nobody").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(not(containsString("WorkFixture Overdue"))));
	}

	@Test
	void candidateQueueShowsDraftNeedingTests() throws Exception {
		mvc.perform(get("/rules/work").param("queue", "candidates").param("search", PREFIX)
				.with(user("editor").authorities(() -> "Rule Modify", () -> "Scan Results View")))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("WorkFixture Drafted")))
				.andExpect(content().string(containsString("Prepare examples and compare")))
				.andExpect(content().string(containsString("/rules/" + drafted + "/candidates")));
	}

	@Test
	void setupQueueSeparatesGapsAndPagesTheFullBacklog() throws Exception {
		for (int i = 0; i < 30; i++) {
			save("Gap " + i, null, null);
		}
		records.flush();
		// 30 gap rules plus the two fixture rules without an owner.
		mvc.perform(get("/rules/work").param("queue", "setup").param("gap", "owner")
				.param("search", PREFIX).with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("1–25 of 32")))
				.andExpect(content().string(containsString("No owner")));
		mvc.perform(get("/rules/work").param("queue", "setup").param("gap", "owner")
				.param("search", PREFIX).param("page", "1").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("26–32 of 32")));
	}

	@Test
	void reportLinksEncodePlusSigns() throws Exception {
		long plus = save("C++ check", null, null).getId();
		long scan = repoScan();
		metric(plus, "repository", scan, 3, System.currentTimeMillis());
		records.flush();
		mvc.perform(get("/rules/work").param("search", "c++").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("/reposcan/report/" + scan + "?reviewSearch=WorkFixture%20C%2B%2B%20check")));
	}

	@Test
	void assignedToMeMatchesTheOwnerExactly() throws Exception {
		save("Lookalike", "alice.b", LocalDate.now(ZoneOffset.UTC).minusDays(2));
		records.flush();
		mvc.perform(get("/rules/work").param("queue", "reviews").param("mine", "true").param("search", PREFIX)
				.with(user("alice").authorities(() -> "Ruleset View")))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("WorkFixture Overdue")))
				.andExpect(content().string(not(containsString("WorkFixture Lookalike"))));
	}

	@Test
	void legacyRulesWithoutAStoredRevisionAreBackfilled() throws Exception {
		records.update("UPDATE RuleEntity r SET r.stewardship.revision=NULL WHERE r.id=?1", unreviewed);
		mvc.perform(get("/rules/work").param("search", PREFIX).with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(not(containsString("WorkFixture Unreviewed"))));
		backfill.backfill();
		mvc.perform(get("/rules/work").param("search", PREFIX).with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("WorkFixture Unreviewed")));
	}

	@Test
	void scanEvidenceQueuesRequireScanResultsView() throws Exception {
		mvc.perform(get("/rules/work").param("queue", "review").param("search", PREFIX).with(reader))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("requires the Scan Results View permission")))
				.andExpect(content().string(not(containsString("WorkFixture Unreviewed"))));
		// Candidate details and editing need Rule Modify: a view-only user sees neither.
		mvc.perform(get("/rules/work").param("queue", "candidates").param("search", PREFIX).with(reader))
				.andExpect(status().isOk())
				.andExpect(content().string(not(containsString("WorkFixture Drafted"))))
				.andExpect(content().string(not(containsString("Narrow the pattern"))));
		mvc.perform(get("/rules/work").param("queue", "setup").param("search", PREFIX).with(reader))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Ask a rule maintainer to set owner and CWE")))
				.andExpect(content().string(not(containsString("/rule/edit/"))));
		// Without scan access the page opens on reviews rather than an empty list.
		mvc.perform(get("/rules/work").param("search", PREFIX).with(reader))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("WorkFixture Overdue")));
		mvc.perform(get("/rules/work").with(user("nobody").authorities(() -> "Scan Results View")))
				.andExpect(status().isForbidden());
	}

	@Test
	void rowsAreDrawnAsScannerTilesChipsAndOneOutlinedAction() throws Exception {
		mvc.perform(get("/rules/work").param("search", PREFIX).with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("data-tip=\"Regex rule\"")))
				.andExpect(content().string(containsString("0 of 6 reviewed")))
				.andExpect(content().string(containsString("What is this?")))
				.andExpect(content().string(not(containsString("About this list"))))
				.andExpect(content().string(not(containsString("repository scan 7"))));
		mvc.perform(get("/rules/work").param("queue", "investigate").param("search", PREFIX).with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString(">Noisy<")))
				.andExpect(content().string(containsString("8 of 10 false positives (80%)")));
		mvc.perform(get("/rules/work").param("queue", "candidates").param("search", "nothing-matches-this").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Nothing to decide right now")));
	}

	@Test
	void setupGapsSetOwnerAndCweForSelectedRulesInOneChange() throws Exception {
		long first = save("Bulk one", null, null).getId();
		long second = save("Bulk two", null, null).getId();
		records.flush();
		var editor = user("editor").authorities(() -> "Rule Modify", () -> "Ruleset View");
		mvc.perform(get("/rules/work").param("queue", "setup").param("search", PREFIX + "Bulk").with(editor))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Set owner and CWE for selected")))
				.andExpect(content().string(containsString("missing an owner, a CWE or recent matches")));
		mvc.perform(post("/rules/work/setup").with(editor).with(csrf())
				.param("ruleId", String.valueOf(first), String.valueOf(second))
				.param("owner", "appsec team").param("cwe", "CWE-79").param("scanner", "regex"))
				.andExpect(status().is3xxRedirection())
				.andExpect(flash().attribute("success", "Saved for 2 rules."))
				.andExpect(redirectedUrl("/rules/work?queue=setup&search=&owner=&mine=false&days=30&gap=all"
						+ "&scanner=regex&pageSize=25"));
		for (long id : new long[] {first, second}) {
			var stewardship = rules.findById(id).orElseThrow().getStewardship();
			org.junit.jupiter.api.Assertions.assertEquals("appsec team", stewardship.getOwner());
			org.junit.jupiter.api.Assertions.assertEquals("CWE-79", stewardship.getCwe());
		}
		// A blank CWE keeps each rule's own; an invalid one changes nothing.
		mvc.perform(post("/rules/work/setup").with(editor).with(csrf())
				.param("ruleId", String.valueOf(first)).param("owner", "platform").param("cwe", ""))
				.andExpect(flash().attribute("success", "Saved for 1 rule."));
		org.junit.jupiter.api.Assertions.assertEquals("CWE-79", rules.findById(first).orElseThrow().getStewardship().getCwe());
		mvc.perform(post("/rules/work/setup").with(editor).with(csrf())
				.param("ruleId", String.valueOf(second)).param("owner", "other").param("cwe", "79"))
				.andExpect(flash().attributeExists("failure"));
		org.junit.jupiter.api.Assertions.assertEquals("appsec team",
				rules.findById(second).orElseThrow().getStewardship().getOwner());
	}

	@Test
	void bulkSetupNeedsRuleModifyAndAKnownScanner() throws Exception {
		long rule = save("Guarded", null, null).getId();
		records.flush();
		mvc.perform(post("/rules/work/setup").with(viewer).with(csrf())
				.param("ruleId", String.valueOf(rule)).param("owner", "someone"))
				.andExpect(status().isForbidden());
		org.junit.jupiter.api.Assertions.assertNull(rules.findById(rule).orElseThrow().getStewardship().getOwner());
		mvc.perform(get("/rules/work").param("queue", "setup").param("search", PREFIX + "Guarded").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(not(containsString("Set owner and CWE for selected"))));
		mvc.perform(get("/rules/work").param("queue", "setup").param("scanner", "bogus").with(viewer))
				.andExpect(status().isBadRequest());
		mvc.perform(get("/rules/work").param("queue", "setup").param("scanner", "regex")
				.param("search", PREFIX + "Guarded").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString(">WorkFixture Guarded<")));
		mvc.perform(get("/rules/work").param("queue", "setup").param("scanner", "pmd")
				.param("search", PREFIX + "Guarded").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(not(containsString(">WorkFixture Guarded<"))));
	}

	@Test
	void everyQueueReadsRulesAsValuesNotEntities() throws Exception {
		// Loading a rule pulls in its rulesets and their rules (the Rulesets page took over 30 s
		// that way). The queues read plain values, so no rule or ruleset entity is loaded.
		ruleService.moduleOfType(com.tracelink.appsec.module.regex.model.RegexRuleEntity.class);
		entities.flush();
		entities.clear();
		Statistics statistics = entityManagerFactory.unwrap(SessionFactory.class).getStatistics();
		statistics.clear();
		UserRequestPostProcessor maintainer = user("maintainer")
				.authorities(() -> "Ruleset View", () -> "Scan Results View", () -> "Rule Modify");
		for (String queue : List.of("review", "investigate", "reviews", "candidates", "setup")) {
			mvc.perform(get("/rules/work").param("queue", queue).param("search", PREFIX).with(maintainer))
					.andExpect(status().isOk())
					.andExpect(content().string(containsString("WorkFixture")));
		}
		assertEquals(0, ruleLoads(statistics), "rule work rows must not load rule or ruleset entities");

		// The measurement itself sees a rule load (so the zero above is not vacuous).
		entities.clear();
		rules.findById(noisy).orElseThrow();
		org.junit.jupiter.api.Assertions.assertTrue(ruleLoads(statistics) > 0);
	}

	private static long ruleLoads(Statistics statistics) {
		return Arrays.stream(statistics.getEntityNames()).filter(RuleWorkMvcTest::ruleOrRuleset)
				.mapToLong(name -> statistics.getEntityStatistics(name).getLoadCount()).sum();
	}

	@Test
	void invalidFiltersAreRejected() throws Exception {
		mvc.perform(get("/rules/work").param("queue", "bogus").with(viewer)).andExpect(status().isBadRequest());
		mvc.perform(get("/rules/work").param("pageSize", "101").with(viewer)).andExpect(status().isBadRequest());
		mvc.perform(get("/rules/work").param("days", "45").with(viewer)).andExpect(status().isBadRequest());
		mvc.perform(get("/rules/work").param("queue", "setup").param("gap", "bogus").with(viewer))
				.andExpect(status().isBadRequest());
	}

	private RuleEntity save(String name, String owner, LocalDate reviewBy) {
		var dto = new RegexCustomRuleDto();
		dto.setName(PREFIX + name);
		dto.setAuthor("reviewer");
		dto.setMessage("Work match");
		dto.setExternalUrl("https://example.test/rule");
		dto.setPriority(RulePriority.HIGH);
		dto.setRegexPattern("unsafe|risky");
		dto.setFileExtension("");
		RuleEntity entity = dto.toEntity();
		entity.getStewardship().setOwner(owner);
		entity.getStewardship().setReviewBy(reviewBy);
		return rules.saveAndFlush(entity);
	}

	/** A real scan row: links to scans that no longer exist are deliberately left out. */
	private long repoScan() {
		var repo = new RepositoryEntity();
		repo.setApiLabel("bb");
		repo.setRepoName("work-fixture-" + UUID.randomUUID());
		repo.setScanType(CodeScanType.PULL_REQUEST);
		var plan = new RepoScanPlanEntity();
		plan.setName("work-fixture");
		plan.setApiLabel("bb");
		plan.setRepoSelector("*");
		plan.setFrequency(PlanFrequency.ONCE);
		plan.setCreatedBy("test");
		var scan = new RepoScanEntity();
		scan.setRepository(repositories.saveAndFlush(repo));
		scan.setPlanId(repoScanPlans.saveAndFlush(plan).getId());
		scan.setRunNo(1);
		scan.setBranch("main");
		scan.setCommitHash("0123456789abcdef0123456789abcdef01234567");
		scan.setStatus(ScanStatus.DONE);
		return repoScans.saveAndFlush(scan).getId();
	}

	private void metric(long ruleId, String scanType, long scanId, long findings, long at) {
		RuleEntity rule = rules.findById(ruleId).orElseThrow();
		var row = new RuleMetricScanEntity(scanType, scanId, UUID.randomUUID().toString().replace("-", ""),
				ruleId, revision(rule), "regex", at, findings, 0L, 0L, null, "UNKNOWN", at);
		row.engineStatus = "RAN";
		records.insert(row);
	}

	private void feedback(long ruleId, String scanType, long scanId, String judgment, long at) {
		RuleEntity rule = rules.findById(ruleId).orElseThrow();
		records.insert(new FindingFeedbackEntity(UUID.randomUUID().toString().replace("-", "")
				+ UUID.randomUUID().toString().replace("-", ""), scanType, scanId, "k", ruleId,
				revision(rule), true, at, judgment, "OTHER", "checked", "reviewer", at, 1L));
	}

	private static boolean ruleOrRuleset(String entityName) {
		try {
			Class<?> type = Class.forName(entityName);
			return RuleEntity.class.isAssignableFrom(type)
					|| com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity.class.isAssignableFrom(type);
		} catch (ClassNotFoundException notAClass) {
			return false;
		}
	}

	private static String revision(RuleEntity rule) {
		return rule.toDto().getRevision();
	}
}
