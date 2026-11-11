package com.tracelink.appsec.watchtower.web;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.UserRequestPostProcessor;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleRepository;
import com.tracelink.appsec.watchtower.core.rule.RuleState;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetRepository;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;

/**
 * Rulesets page (UAT walkthrough, 2026-10-16): one paged rule table with All / Its own / Included
 * tabs read from the database a page at a time. The page took over 30 seconds when it built every
 * ruleset with every rule; it must not do that again.
 */
@SpringBootTest(properties = {"watchtower.runAfterStartup=false", "watchtower.rule-testing.enabled=false",
		"spring.datasource.url=jdbc:h2:mem:uat-rulesets;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"})
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@Transactional
class RulesetPageMvcTest {
	private static final String PREFIX = "RulesetFixture ";

	@MockitoBean
	com.tracelink.appsec.watchtower.web.dev.DevelopmentSetup developmentSetup;
	@MockitoSpyBean
	RulesetService rulesets;
	@Autowired
	MockMvc mvc;
	@Autowired
	RuleRepository rules;
	@Autowired
	RulesetRepository rulesetRepository;

	private final UserRequestPostProcessor viewer = user("viewer").authorities(() -> "Ruleset View");

	private long parent;

	@BeforeEach
	void seed() {
		// Parent owns 2 rules (one retired, so it never counts) and includes Middle, which owns 3
		// and includes Leaf with 30 more: 2 own (1 active) + 33 included = 34 rules that run.
		Set<RuleEntity> own = Set.of(rule("Own placeholder", "Consider giving {0} package visibility."),
				retired(rule("Own retired", "Old")));
		Set<RuleEntity> middleRules = new HashSet<>();
		for (int i = 0; i < 3; i++) {
			middleRules.add(rule("Middle " + i, "Middle message"));
		}
		Set<RuleEntity> leafRules = new HashSet<>();
		for (int i = 10; i < 40; i++) {
			leafRules.add(rule("Leaf " + i, "Leaf message"));
		}
		RulesetEntity leaf = ruleset("Leaf", RulesetDesignation.SUPPORTING, leafRules, Set.of());
		RulesetEntity middle = ruleset("Middle", RulesetDesignation.SUPPORTING, middleRules, Set.of(leaf));
		parent = ruleset("Parent", RulesetDesignation.PRIMARY, own, Set.of(middle)).getId();
		Mockito.clearInvocations(rulesets);
	}

	@Test
	void tabsCountEachScopeAndTheTablePagesOnTheServer() throws Exception {
		String html = mvc.perform(get("/rulesets/" + parent).with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("34 rules")))
				.andExpect(content().string(containsString("Includes 2 rulesets")))
				.andExpect(content().string(containsString("1–25 of 34")))
				.andExpect(content().string(not(containsString(PREFIX + "Own retired"))))
				.andReturn().getResponse().getContentAsString();
		assertEquals(25, html.split("data-rule-row", -1).length - 1, "only one page of rules is rendered");
		// The page reads rulesets as rows and rules one page at a time; it never builds every
		// ruleset with every rule (that took over 30 seconds on Dev).
		Mockito.verify(rulesets, Mockito.never()).getRulesets();
		Mockito.verify(rulesets, Mockito.never()).getDefaultRuleset();

		mvc.perform(get("/rulesets/" + parent).param("scope", "own").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString(PREFIX + "Own placeholder")))
				.andExpect(content().string(containsString("This ruleset")))
				.andExpect(content().string(containsString("Consider giving this member package visibility.")))
				.andExpect(content().string(not(containsString("{0}"))))
				.andExpect(content().string(not(containsString(PREFIX + "Middle 0"))));
		mvc.perform(get("/rulesets/" + parent).param("scope", "included").param("page", "1").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("26–33 of 33")))
				.andExpect(content().string(containsString(PREFIX + "Middle 2")))
				.andExpect(content().string(containsString(PREFIX + "Middle</span>")))
				.andExpect(content().string(not(containsString(PREFIX + "Own placeholder"))));
	}

	@Test
	void scannerAndSeverityFiltersNarrowTheTable() throws Exception {
		mvc.perform(get("/rulesets/" + parent).param("scanner", "regex").param("severity", "LOW").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("Severity: Low")))
				.andExpect(content().string(containsString("Nothing matches the Scanner and Severity filters.")));
		mvc.perform(get("/rulesets/" + parent).param("scanner", "regex").param("severity", "HIGH").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("1–25 of 34")));
		mvc.perform(get("/rulesets/" + parent).param("scanner", "pmd").with(viewer))
				.andExpect(status().isOk())
				.andExpect(content().string(not(containsString("data-rule-row"))));
	}

	private RuleEntity rule(String name, String message) {
		var dto = new RegexCustomRuleDto();
		dto.setName(PREFIX + name);
		dto.setAuthor("reviewer");
		dto.setMessage(message);
		dto.setExternalUrl("https://example.test/rule");
		dto.setPriority(RulePriority.HIGH);
		dto.setRegexPattern("unsafe");
		dto.setFileExtension("");
		return rules.saveAndFlush(dto.toEntity());
	}

	private RulesetEntity ruleset(String name, RulesetDesignation designation, Set<RuleEntity> owned,
			Set<RulesetEntity> included) {
		RulesetEntity ruleset = new RulesetEntity();
		ruleset.setName(PREFIX + name);
		ruleset.setDescription(name);
		ruleset.setDesignation(designation);
		ruleset.setRules(new HashSet<>(owned));
		ruleset.setRulesets(new HashSet<>(included));
		return rulesetRepository.saveAndFlush(ruleset);
	}

	private RuleEntity retired(RuleEntity rule) {
		rule.getStewardship().setState(RuleState.RETIRED);
		return rules.saveAndFlush(rule);
	}
}
