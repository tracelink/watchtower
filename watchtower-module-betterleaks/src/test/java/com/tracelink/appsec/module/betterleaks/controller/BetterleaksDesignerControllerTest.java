package com.tracelink.appsec.module.betterleaks.controller;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksRuleTestResult;
import com.tracelink.appsec.module.betterleaks.service.BetterleaksRuleService;
import com.tracelink.appsec.module.betterleaks.service.BetterleaksRuleTester;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class BetterleaksDesignerControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private BetterleaksRuleTester tester;

	@MockitoBean
	private BetterleaksRuleService ruleService;

	private static MockHttpServletRequestBuilder submit(String action) {
		return MockMvcRequestBuilders.post("/designer/betterleaks")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("action", action)
				.param("ruleId", "custom-example-internal-token")
				.param("description", "An example internal token.")
				.param("externalUrl", "https://wiki.example.invalid/secrets")
				.param("priority", "HIGH")
				.param("regex", "tlk_int_[A-Za-z0-9]{16}")
				.param("keywords", "tlk_int_")
				.param("positiveSample", "key = tlk_int_Q7m2Zp9Xc4Vb8Nn1")
				.param("negativeSample", "key = tlk_int_short");
	}

	@Test
	@WithMockUser(username = "alice", authorities = BetterleaksModule.RULE_DESIGNER_PRIVILEGE_NAME)
	public void testTestShowsTheResultWithoutSaving() throws Exception {
		BDDMockito.when(tester.test(BDDMockito.any()))
				.thenReturn(new BetterleaksRuleTestResult(true, true, null));

		mockMvc.perform(submit("test"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("also matches its negative sample")));

		BDDMockito.verifyNoInteractions(ruleService);
	}

	@Test
	@WithMockUser(username = "alice", authorities = BetterleaksModule.RULE_DESIGNER_PRIVILEGE_NAME)
	public void testSaveStoresTheRuleAsTheUser() throws Exception {
		mockMvc.perform(submit("save"))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString("Betterleaks: custom-example-internal-token")));

		BDDMockito.verify(ruleService).saveNewCustomRule(BDDMockito.argThat(rule ->
				rule.getRegex().equals("tlk_int_[A-Za-z0-9]{16}")), BDDMockito.eq("alice"));
	}

	@Test
	@WithMockUser(username = "alice", authorities = BetterleaksModule.RULE_DESIGNER_PRIVILEGE_NAME)
	public void testSaveFailureIsShownOnTheDesigner() throws Exception {
		BDDMockito.when(ruleService.saveNewCustomRule(BDDMockito.any(), BDDMockito.any()))
				.thenThrow(new IllegalArgumentException("The rule does not match its positive"
						+ " sample."));

		mockMvc.perform(submit("save"))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("does not match its positive sample")));
	}

	@Test
	@WithMockUser(authorities = BetterleaksModule.RULE_EDITOR_PRIVILEGE_NAME)
	public void testDesigningNeedsTheDesignerPrivilege() throws Exception {
		mockMvc.perform(submit("save")).andExpect(MockMvcResultMatchers.status().isForbidden());
		BDDMockito.verifyNoInteractions(ruleService);
	}
}
