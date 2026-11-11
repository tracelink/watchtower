package com.tracelink.appsec.watchtower.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.draft.RuleDraftService;

/**
 * A rule drafted for a coverage gap opens in the real designers with its rule and example filled in, and saving it
 * there gives the new rule its owner and CWE and closes the draft. This runs outside a test transaction on purpose:
 * in the application the designer's save is committed before the draft follows it.
 */
@SpringBootTest(properties = {"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false",
		"spring.datasource.url=jdbc:h2:mem:draft-designers;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class RuleDraftDesignersMvcTest {
	private static final String RULE_NAME = "Draft e2e: no http URLs";

	@MockitoBean
	com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
	@Autowired
	MockMvc mvc;
	@Autowired
	RuleDraftService drafts;
	@Autowired
	RuleService rules;

	private final UserRequestPostProcessor alice = user("alice").authorities(() -> "Rule Designer", () -> "Regex Rule Designer",
			() -> "PMD Rule Designer", () -> "JSON Rule Designer", () -> "Rule Modify");
	private final UserRequestPostProcessor bob = user("bob").authorities(() -> "Rule Designer", () -> "Regex Rule Designer");

	@AfterEach
	void removeTheRule() throws Exception {
		rules.invalidateRuleCache();
		RuleEntity saved = rules.getRule(RULE_NAME);
		if (saved != null) {
			rules.deleteRule(saved.getId());
		}
	}

	private RuleDraftData regexDraft() {
		return new RuleDraftData(null, "regex", null, RULE_NAME, "Use https.", 3, "CWE-319", "CWE-200", "\"http://", ".java",
				"String a = 1;\nString u = \"http://example.com\";", "String u = \"https://example.com\";",
				"Plain http is readable on the network.", "Coverage gap: CWE-319 · Java (assistant draft)");
	}

	@Test
	void aRegexDraftOpensWithItsPatternItsExampleItsMatchAndABanner() throws Exception {
		String id = drafts.create("alice", regexDraft()).id();

		mvc.perform(get("/designer/regex").param("draft", id).with(alice)).andExpect(status().isOk())
				.andExpect(content().string(containsString("data-draft-banner")))
				.andExpect(content().string(containsString("AI draft · nothing saved")))
				.andExpect(content().string(containsString("CWE-319, CWE-200")))
				.andExpect(content().string(containsString("/designer/draft/" + id + "/discard")))
				.andExpect(content().string(containsString("&quot;http://")))
				.andExpect(content().string(containsString("data-designer-match-line=\"2\"")))
				.andExpect(content().string(containsString("value=\"" + RULE_NAME + "\"")))
				.andExpect(content().string(containsString("Should not be flagged")));
	}

	@Test
	void anotherPersonGetsThePlainDesignerAndAnExplanation() throws Exception {
		String id = drafts.create("alice", regexDraft()).id();

		mvc.perform(get("/designer/regex").param("draft", id).with(bob)).andExpect(status().isOk())
				.andExpect(content().string(not(containsString("data-draft-banner"))))
				.andExpect(content().string(containsString("no longer available")));
	}

	@Test
	void savingTheDraftedRuleGivesItsOwnerAndCweAndClosesTheDraft() throws Exception {
		String id = drafts.create("alice", regexDraft()).id();

		mvc.perform(post("/designer/regex/save").with(alice).with(csrf()).param("name", RULE_NAME).param("message", "Use https.")
				.param("fileExtension", ".java").param("priority", "3").param("query", "\"http://").param("externalUrl", "https://example.test/rule")
				.param("source", "String u = \"http://example.com\";").param("draft", id)).andExpect(status().isOk())
				.andExpect(content().string(containsString("Created rule: " + RULE_NAME)));

		rules.invalidateRuleCache();
		RuleEntity saved = rules.getRule(RULE_NAME);
		assertThat(saved).isNotNull();
		assertThat(saved.getStewardship().getOwner()).isEqualTo("alice");
		assertThat(saved.getStewardship().getCwe()).isEqualTo("CWE-319");
		assertThat(saved.getStewardship().getSecondaryCwes()).isEqualTo("CWE-200");
		assertThat(drafts.open(id, "alice", "regex")).as("the draft is used up").isEmpty();
	}

	@Test
	void aSaveThatFailsKeepsTheDraftAndItsBannerForAnotherTry() throws Exception {
		String id = drafts.create("alice", regexDraft()).id();

		mvc.perform(post("/designer/regex/save").with(alice).with(csrf()).param("name", "").param("message", "Use https.")
				.param("fileExtension", ".java").param("priority", "3").param("query", "\"http://").param("externalUrl", "")
				.param("source", "x").param("draft", id)).andExpect(status().isOk())
				.andExpect(content().string(containsString("Failed to validate")))
				.andExpect(content().string(containsString("data-draft-banner")));

		assertThat(drafts.open(id, "alice", "regex")).isPresent();
		assertThat(rules.getRule("")).isNull();
	}

	@Test
	void aSaveWithSomeoneElsesDraftIdChangesNothingAboutTheRulesOwnerOrCwe() throws Exception {
		String id = drafts.create("alice", regexDraft()).id();

		mvc.perform(post("/designer/regex/save").with(bob).with(csrf()).param("name", RULE_NAME).param("message", "Use https.")
				.param("fileExtension", ".java").param("priority", "3").param("query", "\"http://").param("externalUrl", "https://example.test/rule")
				.param("source", "x").param("draft", id)).andExpect(status().isOk());

		rules.invalidateRuleCache();
		RuleEntity saved = rules.getRule(RULE_NAME);
		assertThat(saved).isNotNull();
		assertThat(saved.getStewardship().getCwe()).as("bob did not own the draft").isNull();
		assertThat(drafts.open(id, "alice", "regex")).as("and alice's draft is still hers").isPresent();
	}

	@Test
	void aPmdDraftOpensWithItsXPathRunOnItsExample() throws Exception {
		String id = drafts.create("alice", new RuleDraftData(null, "pmd", "Java", "Draft e2e: no System.out", "Use the logger.", 4, "CWE-532", null,
				"//MethodCall[@MethodName = \"println\"]", null,
				"public class A {\n    void m(String id) {\n        System.out.println(id);\n    }\n}", "class B {}",
				"Console output is not logged safely.", "Coverage gap: CWE-532 · Java (assistant draft)")).id();

		mvc.perform(get("/designer/pmd").param("draft", id).with(alice)).andExpect(status().isOk())
				.andExpect(content().string(containsString("data-draft-banner")))
				.andExpect(content().string(containsString("data-designer-match-line=\"3\"")))
				.andExpect(content().string(containsString("CWE-532")));
	}

	@Test
	void aJsonDraftOpensWithItsQueryRunOnItsExample() throws Exception {
		String id = drafts.create("alice", new RuleDraftData(null, "json", "json", "Draft e2e: debug on", "Turn debug off.", 3, "CWE-489", null,
				"$[?(@.debug == true)]", ".json", "{\"debug\": true}", "{\"debug\": false}", "Debug mode leaks internals.",
				"Coverage gap: CWE-489 (assistant draft)")).id();

		mvc.perform(get("/designer/json").param("draft", id).with(alice)).andExpect(status().isOk())
				.andExpect(content().string(containsString("data-draft-banner")))
				.andExpect(content().string(containsString("1 match")));
	}
}
