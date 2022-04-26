package com.tracelink.appsec.module.advisory.controller;

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

import com.tracelink.appsec.module.advisory.AdvisoryModule;
import com.tracelink.appsec.module.advisory.designer.AdvisoryRuleDesigner;
import com.tracelink.appsec.module.advisory.service.AdvisoryRuleService;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageAdvisoryService;
import com.tracelink.appsec.watchtower.test.WatchtowerTestApplication;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class AdvisoryDesignerControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private AdvisoryRuleDesigner ruleDesigner;

	@MockBean
	private RuleDesignerService ruleDesignerService;

	@MockBean
	private ImageAdvisoryService imageAdvisoryService;

	@MockBean
	private AdvisoryRuleService ruleService;


	@Test
	@WithMockUser(authorities = {AdvisoryModule.ADVISORY_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveRule() throws Exception {
		String name = "name";
		AdvisoryEntity mockAdvisory = BDDMockito.mock(AdvisoryEntity.class);
		BDDMockito.when(mockAdvisory.getAdvisoryName()).thenReturn(name);
		BDDMockito.when(imageAdvisoryService.findByName(BDDMockito.anyString()))
				.thenReturn(mockAdvisory);
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(null);
		BDDMockito.when(ruleDesigner.getDefaultRuleDesignerModelAndView()).thenReturn(mav);

		mockMvc.perform(MockMvcRequestBuilders.post("/designer/advisory/save")
				.param("advisoryName", name).with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString("Successfully Saved Rule " + name)));
	}

	@Test
	@WithMockUser(authorities = {AdvisoryModule.ADVISORY_RULE_DESIGNER_PRIVILEGE_NAME})
	public void testSaveRuleException() throws Exception {
		String name = "name";
		AdvisoryEntity mockAdvisory = BDDMockito.mock(AdvisoryEntity.class);
		BDDMockito.when(mockAdvisory.getAdvisoryName()).thenReturn(name);
		BDDMockito.when(imageAdvisoryService.findByName(BDDMockito.anyString()))
				.thenReturn(mockAdvisory);
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(null);
		BDDMockito.when(ruleDesigner.getDefaultRuleDesignerModelAndView()).thenReturn(mav);
		BDDMockito.willThrow(new RuleDesignerException("exception")).given(ruleService)
				.saveNewRule(BDDMockito.any());
		mockMvc.perform(MockMvcRequestBuilders.post("/designer/advisory/save")
				.param("advisoryName", name).with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.model().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("exception")));
	}

}
