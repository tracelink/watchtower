package com.tracelink.appsec.module.regex.controller;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.module.regex.RegexModule;
import com.tracelink.appsec.module.regex.designer.RegexRuleDesigner;
import com.tracelink.appsec.module.regex.service.RegexRuleService;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RegexDesignerControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private RegexRuleService ruleService;

	@MockBean
	private RegexRuleDesigner ruleDesigner;

	@MockBean
	private RuleDesignerService ruleDesignerService;

	@Test
	@WithMockUser(authorities = {RegexModule.REGEX_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveRule() throws Exception {
		String name = "RuleName";
		String message = "message";
		String fileExtension = ".txt";
		String priority = "1";
		String query = "test";
		String externalUrl = "foobar";
		String source = "test String";

		BDDMockito.when(ruleDesigner.query(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(new RuleDesignerModelAndView(null));

		mockMvc.perform(MockMvcRequestBuilders.post("/designer/regex/save")
				.param("name", name)
				.param("message", message)
				.param("fileExtension", fileExtension)
				.param("priority", priority)
				.param("query", query)
				.param("externalUrl", externalUrl)
				.param("source", source)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attributeDoesNotExist("ruleName",
						"ruleMessage", "rulefileExtension", "rulePriority"))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString("Created rule")));
	}

	@Test
	@WithMockUser(authorities = {RegexModule.REGEX_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveRuleFailSave() throws Exception {
		String name = "RuleName";
		String message = "message";
		String fileExtension = ".txt";
		String priority = "1";
		String query = "test";
		String externalUrl = "foobar";
		String source = "test String";

		BDDMockito.when(ruleDesigner.query(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(new RuleDesignerModelAndView(null));
		BDDMockito.willThrow(new RuleDesignerException("")).given(ruleService)
				.saveNewRule(BDDMockito.any());

		mockMvc.perform(MockMvcRequestBuilders.post("/designer/regex/save")
				.param("name", name)
				.param("message", message)
				.param("fileExtension", fileExtension)
				.param("priority", priority)
				.param("query", query)
				.param("externalUrl", externalUrl)
				.param("source", source)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attributeDoesNotExist("ruleName",
						"ruleMessage", "rulefileExtension", "rulePriority"))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot save rule")));
	}

	@Test
	@WithMockUser(authorities = {RegexModule.REGEX_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveRuleFailValidation() throws Exception {
		String name = "RuleName";
		String message = "message";
		String fileExtension = ".txt";
		String priority = "1";
		String query = "test";
		String externalUrl = ""; // Validation error
		String source = "test String";

		BDDMockito.when(ruleDesigner.query(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(new RuleDesignerModelAndView(null));

		mockMvc.perform(MockMvcRequestBuilders.post("/designer/regex/save")
				.param("name", name)
				.param("message", message)
				.param("fileExtension", fileExtension)
				.param("priority", priority)
				.param("query", query)
				.param("externalUrl", externalUrl)
				.param("source", source)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute("ruleName", name))
				.andExpect(MockMvcResultMatchers.model().attribute("ruleMessage", message))
				.andExpect(
						MockMvcResultMatchers.model().attribute("ruleFileExt", fileExtension))
				.andExpect(MockMvcResultMatchers.model().attribute("rulePriority",
						Integer.parseInt(priority)))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Failed to validate")));
	}

	@Test
	@WithMockUser(authorities = {RegexModule.REGEX_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testQuery() throws Exception {
		String query = "//";
		String source = "test String";

		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(null);
		BDDMockito.when(ruleDesigner.query(BDDMockito.anyString(), BDDMockito.anyString()))
				.thenReturn(mav);

		mockMvc.perform(MockMvcRequestBuilders.post("/designer/regex/query")
				.param("query", query)
				.param("source", source)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute("designerView",
						Matchers.nullValue()));
	}
}
