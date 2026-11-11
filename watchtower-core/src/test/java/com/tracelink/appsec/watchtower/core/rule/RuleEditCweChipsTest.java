package com.tracelink.appsec.watchtower.core.rule;

import java.util.Collections;
import java.util.List;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.cwe.CweCatalogService;
import com.tracelink.appsec.watchtower.core.mock.MockRuleEntity;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;

/**
 * The rule page renders the rule's CWE chips. A template expression Thymeleaf refuses only fails once a rule has a
 * CWE, so this renders a rule that has one (the page broke on a real instance before there was a test for it).
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
class RuleEditCweChipsTest {
	@Autowired
	private MockMvc mockMvc;
	@MockitoBean
	private RuleService ruleService;
	@MockitoBean
	private RuleEditorService editor;

	private RuleEditModelAndView pageFor(MockRuleEntity rule) throws Exception {
		RuleEditModelAndView mav = new RuleEditModelAndView(null);
		mav.addObject("modules", Collections.singleton("test"));
		mav.addObject("rules", List.of(rule.toDto()));
		mav.addObject("activeModule", "test");
		mav.addObject("activeRule", rule.toDto());
		mav.addObject("customCount", 1);
		mav.addObject("providedCount", 0);
		mav.addObject("ruleView", "rule-mgmt/mock");
		mav.addObject("cweChips", List.of());
		BDDMockito.when(editor.getRuleEditModelAndView("test", rule.getId())).thenReturn(mav);
		return mav;
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	void theChipsShowThePrimaryAndSecondaryCwesWithTheirNamesAndAmberWhenNotAllowed() throws Exception {
		MockRuleEntity rule = new MockRuleEntity();
		rule.getStewardship().setCwe("CWE-89");
		rule.getStewardship().setSecondaryCwes("CWE-564,CWE-74");
		RuleEditModelAndView mav = pageFor(rule);
		mav.addObject("cweChips", List.of(
				new CweCatalogService.ChipView("CWE-89", "CWE-89 · SQL Injection\nPrimary: used for coverage and reports", false, true),
				new CweCatalogService.ChipView("CWE-564", "CWE-564 · SQL Injection: Hibernate\nSecondary", false, false),
				new CweCatalogService.ChipView("CWE-74", "CWE-74 · Injection\nSecondary", true, false)));

		String html = mockMvc.perform(MockMvcRequestBuilders.get("/rule/edit/test/" + rule.getId()))
				.andExpect(MockMvcResultMatchers.status().isOk()).andReturn().getResponse().getContentAsString();

		org.junit.jupiter.api.Assertions.assertTrue(html.contains(">CWE-89</span>"), "primary chip");
		org.junit.jupiter.api.Assertions.assertTrue(html.contains(">CWE-564</span>"), "secondary chip");
		org.junit.jupiter.api.Assertions.assertTrue(html.contains("SQL Injection: Hibernate"), "its name is on hover");
		org.junit.jupiter.api.Assertions.assertTrue(html.matches("(?s).*wt-mini-chip--warn[^>]*data-tip=\"CWE-74.*"),
				"a CWE MITRE discourages is amber");
		org.junit.jupiter.api.Assertions.assertFalse(html.contains("it has no CWE and is not counted as a gap"),
				"the header chip for a non-security rule is not shown for a rule that has a CWE");
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_MODIFY_NAME})
	void aRuleMarkedNotASecurityRuleSaysSoAndShowsNoCweChip() throws Exception {
		MockRuleEntity rule = new MockRuleEntity();
		rule.getStewardship().setSecurityRelevance(RuleStewardship.NOT_SECURITY);
		pageFor(rule);

		mockMvc.perform(MockMvcRequestBuilders.get("/rule/edit/test/" + rule.getId()))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(Matchers.containsString("it has no CWE and is not counted as a gap")));
	}
}
