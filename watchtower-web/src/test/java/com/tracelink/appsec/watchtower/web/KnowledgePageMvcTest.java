package com.tracelink.appsec.watchtower.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.LocalDate;
import java.util.UUID;

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
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.persistence.RuleReviewItemEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleRepository;
import com.tracelink.appsec.watchtower.core.rule.knowledge.KnowledgeEntity;
import com.tracelink.appsec.watchtower.core.rule.knowledge.KnowledgeRepository;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanType;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/** Knowledge as a page: names instead of IDs, status headings, searchable pickers and permissions. */
@SpringBootTest(properties = {"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false",
		"spring.datasource.url=jdbc:h2:mem:uat-knowledge;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Transactional
class KnowledgePageMvcTest {
	@MockitoBean
	com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
	@Autowired
	MockMvc mvc;
	@Autowired
	RuleRepository rules;
	@Autowired
	RepositoryRepository repositories;
	@Autowired
	KnowledgeRepository knowledge;
	@Autowired
	LedgerRepository records;

	private final UserRequestPostProcessor viewer =
			user("viewer").authorities(() -> "Ruleset View", () -> "Scan Results View");
	private final UserRequestPostProcessor approver =
			user("bob").authorities(() -> "Ruleset View", () -> "Rule Modify", () -> "Scan Results View");
	private final UserRequestPostProcessor proposer =
			user("alice").authorities(() -> "Ruleset View", () -> "Rule Modify");

	private long ruleId;
	private String reviewId;

	@BeforeEach
	void seed() {
		var dto = new RegexCustomRuleDto();
		dto.setName("Knowledge fixture rule");
		dto.setAuthor("reviewer");
		dto.setMessage("Escaping check");
		dto.setExternalUrl("https://example.test/rule");
		dto.setPriority(RulePriority.HIGH);
		dto.setRegexPattern("forHtml");
		dto.setFileExtension("");
		var rule = rules.saveAndFlush(dto.toEntity());
		ruleId = rule.getId();

		var repository = new RepositoryEntity();
		repository.setApiLabel("bitbucket");
		repository.setRepoName("payments-api");
		repository.setScanType(CodeScanType.PULL_REQUEST);
		long repositoryId = repositories.saveAndFlush(repository).getId();

		reviewId = UUID.randomUUID().toString();
		records.insert(new RuleReviewItemEntity(reviewId, ruleId, rule.toDto().getRevision(), "alice", "ACCEPTED",
				"Encoder sanitizes output", "Treat as sanitized", null, null, null, null, "Confirmed in code review",
				1L, 1L, 1L));
		var content = new KnowledgeEntity.Content("SANITIZER", "<img src=x> Encode.forHtml escapes HTML output", "java",
				"OWASP Java Encoder", "1.2.x", false, "[" + repositoryId + "]", "[" + ruleId + "]", "[\"CWE-79\"]",
				"[{\"type\":\"review\",\"id\":\"" + reviewId + "\"}]", LocalDate.now().plusMonths(6).toString());
		knowledge.saveAndFlush(new KnowledgeEntity(UUID.randomUUID().toString(), content, "alice", 1L));
		records.flush();
	}

	@Test
	void entriesShowNamesHeadingsAndEscapedText() throws Exception {
		mvc.perform(get("/rules/knowledge").param("status", "PROPOSED").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("aria-label=\"Waiting knowledge\"")))
				.andExpect(content().string(containsString(">Waiting</span>")))
				.andExpect(content().string(containsString("class=\"wt-count-badge\">1</span>")))
				.andExpect(content().string(containsString("bitbucket / payments-api")))
				.andExpect(content().string(containsString("Knowledge fixture rule")))
				.andExpect(content().string(containsString("Accepted review: Encoder sanitizes output")))
				.andExpect(content().string(containsString("&lt;img src=x&gt; Encode.forHtml")))
				.andExpect(content().string(not(containsString("data-knowledge-decision"))))
				.andExpect(content().string(not(containsString("data-knowledge-form"))));
		mvc.perform(get("/rules/knowledge").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("data-knowledge-empty")))
				.andExpect(content().string(containsString("No approved knowledge yet")))
				.andExpect(content().string(containsString("Cited by the AI assistant")))
				.andExpect(content().string(not(containsString("About knowledge"))))
				.andExpect(content().string(not(containsString("0–0 of 0"))))
				.andExpect(content().string(not(containsString("knowledgeProposeDialog"))));
	}

	@Test
	void onlyASecondPersonSeesApprove() throws Exception {
		mvc.perform(get("/rules/knowledge").param("status", "PROPOSED").with(approver))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("data-knowledge-decision=\"approve\"")));
		mvc.perform(get("/rules/knowledge").param("status", "PROPOSED").with(proposer))
				.andExpect(status().isOk())
				.andExpect(content().string(not(containsString("data-knowledge-decision=\"approve\""))))
				.andExpect(content().string(containsString("Another person must approve your proposal")));
	}

	@Test
	void proposalPrefillsRuleAndReviewByName() throws Exception {
		mvc.perform(get("/rules/knowledge").param("ruleId", String.valueOf(ruleId)).param("reviewId", reviewId)
				.with(approver))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("data-knowledge-form")))
				.andExpect(content().string(containsString("data-open-on-load=\"true\"")))
				.andExpect(content().string(containsString("data-picker-value=\"" + ruleId + "\"")))
				.andExpect(content().string(containsString("data-picker-value=\"" + reviewId + "\"")));
	}

	@Test
	void pickersSearchByNameAndRespectPermissions() throws Exception {
		mvc.perform(get("/rules/knowledge/options/rules").param("search", "fixture rule").with(approver))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.content[0].id").value(String.valueOf(ruleId)))
				.andExpect(jsonPath("$.content[0].label").value(containsString("Knowledge fixture rule")));
		mvc.perform(get("/rules/knowledge/options/repositories").param("search", "payments").with(approver))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.content[0].label").value("bitbucket / payments-api"));
		mvc.perform(get("/rules/knowledge/options/review").param("ruleIds", String.valueOf(ruleId)).with(approver))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.content[0].id").value(reviewId))
				.andExpect(jsonPath("$.content[0].preview").value(containsString("Confirmed in code review")));
		mvc.perform(get("/rules/knowledge/options/rules").with(viewer)).andExpect(status().isForbidden());
		mvc.perform(get("/rules/knowledge/options/finding_feedback").with(proposer)).andExpect(status().isForbidden());
		mvc.perform(get("/rules/knowledge/options/bogus").with(approver)).andExpect(status().isBadRequest());
	}

	@Test
	void invalidStatusOrPageIsRejected() throws Exception {
		mvc.perform(get("/rules/knowledge").param("status", "DELETED").with(viewer)).andExpect(status().isBadRequest());
		mvc.perform(get("/rules/knowledge").param("pageSize", "101").with(viewer)).andExpect(status().isBadRequest());
		mvc.perform(get("/rules/knowledge").with(user("nobody").authorities(() -> "Scan Results View")))
				.andExpect(status().isForbidden());
	}
}
