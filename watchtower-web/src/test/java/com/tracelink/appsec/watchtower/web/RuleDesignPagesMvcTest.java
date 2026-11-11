package com.tracelink.appsec.watchtower.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleRepository;

/**
 * Rule designers and Rule editing render with the real modules (UAT walkthrough, 2026-10-16): two
 * designer cards with match chips that point at the matched lines, scanner icons on the tabs, and
 * a Rule editing page that opens on a rule with its facts as chips.
 */
@SpringBootTest(properties = {"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false",
		"spring.datasource.url=jdbc:h2:mem:uat-design;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Transactional
class RuleDesignPagesMvcTest {

	@MockitoBean
	com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
	@Autowired
	MockMvc mvc;
	@Autowired
	RuleRepository rules;
	@Autowired
	com.tracelink.appsec.watchtower.core.rule.RuleService ruleService;

	private final UserRequestPostProcessor designer = user("designer").authorities(() -> "Rule Designer",
			() -> "Regex Rule Designer", () -> "PMD Rule Designer", () -> "JSON Rule Designer",
			() -> "Advisory Rule Designer", () -> "Betterleaks Rule Designer");
	private final UserRequestPostProcessor editor = user("editor").authorities(() -> "Rule Modify",
			() -> "Regex Rule Editor", () -> "Advisory Rule Editor");

	@Test
	void codeDesignersShowTwoCardsAndLineChipsForTheirMatches() throws Exception {
		mvc.perform(get("/designer/regex").with(designer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("wt-designer-grid")))
				.andExpect(content().string(containsString("data-designer-match-line=\"2\"")))
				.andExpect(content().string(containsString("Line 2")))
				.andExpect(content().string(containsString("1 match")))
				.andExpect(content().string(containsString("How to write it")))
				// Tabs carry each scanner's icon and readable name.
				.andExpect(content().string(containsString(">pattern</span><span>Regex</span>")))
				.andExpect(content().string(not(containsString("Found on line"))));
		mvc.perform(get("/designer/pmd").with(designer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("data-designer-match-line=\"3\"")))
				.andExpect(content().string(containsString("Syntax")))
				.andExpect(content().string(containsString("XPath rule")));
		mvc.perform(post("/designer/json/query").with(designer).with(csrf()).param("query", "$..privileged")
				.param("code", "privileged: true\n---\nprivileged: true\n").param("sourceFormat", "yaml"))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("data-designer-match-line=\"3\"")))
				.andExpect(content().string(containsString("YAML document 2")))
				.andExpect(content().string(containsString("2 matches")));
	}

	@Test
	void secretsAndAdvisoryDesignersUseTheNewLayout() throws Exception {
		mvc.perform(get("/designer/betterleaks").with(designer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("custom-lower-case-and-dashes")))
				.andExpect(content().string(containsString("made-up values")))
				.andExpect(content().string(containsString("Test rule")))
				.andExpect(content().string(not(containsString("supporting-text=\"Made-up values only\""))));
		mvc.perform(get("/designer/advisory").with(designer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Advisories seen in image scans")))
				.andExpect(content().string(containsString("<span class=\"visually-hidden\">Ignore</span>")))
				.andExpect(content().string(containsString("Ignore advisory")))
				.andExpect(content().string(not(containsString("hitelist"))));
	}

	@Test
	void ruleEditingOpensOnARuleWithChipsAndCounts() throws Exception {
		RuleEntity rule = rule("DesignPages custom");
		mvc.perform(get("/rule/edit/regex").with(editor))
				.andExpect(status().isOk())
				// The first custom rule is open: no empty "Select a rule" box.
				.andExpect(content().string(containsString("id=\"rule-detail-heading\" class=\"h5 m-0\">DesignPages custom<")))
				.andExpect(content().string(not(containsString("Select a rule to view its details."))))
				.andExpect(content().string(containsString("aria-label=\"Author: reviewer\"")))
				.andExpect(content().string(containsString("wt-rule-delete")))
				.andExpect(content().string(containsString(">Custom<span class=\"wt-count-badge\">")))
				.andExpect(content().string(containsString("Search Regex rules")));
		mvc.perform(get("/rule/edit/regex/" + rule.getId()).with(editor))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Owner and status")));
		mvc.perform(get("/rule/edit/advisory").with(editor))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("No advisory rules to edit")))
				.andExpect(content().string(containsString("href=\"/designer/advisory\"")));
	}

	private RuleEntity rule(String name) {
		var dto = new RegexCustomRuleDto();
		dto.setName(name);
		dto.setAuthor("reviewer");
		dto.setMessage("Design pages match");
		dto.setExternalUrl("https://example.test/rule");
		dto.setPriority(RulePriority.HIGH);
		dto.setRegexPattern("unsafe");
		dto.setFileExtension("");
		RuleEntity saved = rules.saveAndFlush(dto.toEntity());
		// The editor lists rules from RuleService's cache, which reloads after a commit; this test
		// never commits, so expire the cache directly.
		org.springframework.test.util.ReflectionTestUtils.setField(ruleService, "ruleCacheLoadedAtMillis", 0L);
		return saved;
	}
}
