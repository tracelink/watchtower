package com.tracelink.appsec.module.pmd.controller;

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

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.module.pmd.designer.PMDRuleDesigner;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class PMDDesignerControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private PMDRuleService ruleService;

	@MockBean
	private PMDRuleDesigner ruleDesigner;

	@MockBean
	private RuleDesignerService ruleDesignerService;

	@Test
	@WithMockUser(authorities = {PMDModule.PMD_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveRule() throws Exception {
		String name = "RuleName";
		String message = "message";
		String description = "description";
		String language = "Java";
		String priority = "1";
		String query = "//";
		String externalUrl = "foobar";
		String source = "public class Foo{}";

		BDDMockito.when(ruleDesigner.query(BDDMockito.anyString(), BDDMockito.anyString(),
				BDDMockito.anyString())).thenReturn(new RuleDesignerModelAndView(null));

		mockMvc.perform(MockMvcRequestBuilders.post("/designer/pmd/save")
				.param("name", name)
				.param("message", message)
				.param("description", description)
				.param("language", language)
				.param("priority", priority)
				.param("query", query)
				.param("externalUrl", externalUrl)
				.param("source", source)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attributeDoesNotExist("ruleName",
						"ruleMessage", "ruleDescription", "rulePriority"))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString("Created rule")));
	}

	@Test
	@WithMockUser(authorities = {PMDModule.PMD_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveRuleFailSave() throws Exception {
		String name = "RuleName";
		String message = "message";
		String description = "description";
		String language = "Java";
		String priority = "1";
		String query = "//";
		String externalUrl = "foobar";
		String source = "public class Foo{}";

		BDDMockito.when(ruleDesigner.query(BDDMockito.anyString(), BDDMockito.anyString(),
				BDDMockito.anyString())).thenReturn(new RuleDesignerModelAndView(null));
		BDDMockito.willThrow(new RuleDesignerException("")).given(ruleService)
				.saveNewRule(BDDMockito.any());

		mockMvc.perform(MockMvcRequestBuilders.post("/designer/pmd/save")
				.param("name", name)
				.param("message", message)
				.param("description", description)
				.param("language", language)
				.param("priority", priority)
				.param("query", query)
				.param("externalUrl", externalUrl)
				.param("source", source)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attributeDoesNotExist("ruleName",
						"ruleMessage", "ruleDescription", "rulePriority"))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot save rule")));
	}

	@Test
	@WithMockUser(authorities = {PMDModule.PMD_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveRuleFailValidation() throws Exception {
		String name = "RuleName";
		String message = "message";
		String description = "description";
		String language = "Java";
		String priority = "1";
		String query = "//";
		String externalUrl = ""; // Validation error
		String source = "public class Foo{}";

		BDDMockito.when(ruleDesigner.query(BDDMockito.anyString(), BDDMockito.anyString(),
				BDDMockito.anyString())).thenReturn(new RuleDesignerModelAndView(null));

		mockMvc.perform(MockMvcRequestBuilders.post("/designer/pmd/save")
				.param("name", name)
				.param("message", message)
				.param("description", description)
				.param("language", language)
				.param("priority", priority)
				.param("query", query)
				.param("externalUrl", externalUrl)
				.param("source", source)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute("ruleName", name))
				.andExpect(MockMvcResultMatchers.model().attribute("ruleMessage", message))
				.andExpect(MockMvcResultMatchers.model().attribute("ruleDescription", description))
				.andExpect(MockMvcResultMatchers.model().attribute("rulePriority",
						Integer.parseInt(priority)))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Failed to validate")));
	}

	@Test
	@WithMockUser(authorities = {PMDModule.PMD_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testQuery() throws Exception {
		String language = "Java";
		String query = "//";
		String source = "public class Foo{}";

		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(null);
		BDDMockito.when(ruleDesigner.query(BDDMockito.anyString(), BDDMockito.anyString(),
				BDDMockito.anyString())).thenReturn(mav);

		mockMvc.perform(MockMvcRequestBuilders.post("/designer/pmd/query")
				.param("language", language)
				.param("query", query)
				.param("source", source)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute("designerView",
						Matchers.nullValue()));
	}
}
