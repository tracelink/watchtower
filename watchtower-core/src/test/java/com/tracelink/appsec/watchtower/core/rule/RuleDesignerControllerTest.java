package com.tracelink.appsec.watchtower.core.rule;

import java.util.Arrays;
import java.util.List;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RuleDesignerControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private RuleDesignerService mockDesignerService;

	///////////////////
	// Get designer
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_DESIGNER_NAME})
	public void testGetDesigner() throws Exception {
		BDDMockito.when(mockDesignerService.getDefaultDesignerModule()).thenReturn("Mock");

		mockMvc.perform(MockMvcRequestBuilders.get("/designer"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/designer/mock"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_DESIGNER_NAME})
	public void testGetDesignerNoDefault() throws Exception {
		BDDMockito.when(mockDesignerService.getDefaultDesignerModule()).thenReturn(null);

		mockMvc.perform(MockMvcRequestBuilders.get("/designer"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("no designers")));
	}

	///////////////////
	// Get Specific Designer
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_DESIGNER_NAME})
	public void testGetLangDesigner() throws Exception {
		RuleDesignerModelAndView mockMAV = new RuleDesignerModelAndView(null);
		List<String> modules = Arrays.asList("Test");

		BDDMockito.when(mockDesignerService.getDefaultDesignerModelAndView(BDDMockito.anyString()))
				.thenReturn(mockMAV);
		BDDMockito.when(mockDesignerService.getKnownModulesForUser(BDDMockito.any()))
				.thenReturn(modules);

		mockMvc.perform(MockMvcRequestBuilders.get("/designer/mock"))
				.andExpect(MockMvcResultMatchers.model().attribute("knownModules",
						Matchers.is(modules)));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_DESIGNER_NAME})
	public void testGetLangDesignerHighlightsActiveModule() throws Exception {
		RuleDesignerModelAndView mockMAV = new RuleDesignerModelAndView(null);
		List<String> modules = Arrays.asList("Mock", "Other");

		BDDMockito.when(mockDesignerService.getDefaultDesignerModelAndView(BDDMockito.anyString()))
				.thenReturn(mockMAV);
		BDDMockito.when(mockDesignerService.getKnownModulesForUser(BDDMockito.any()))
				.thenReturn(modules);

		mockMvc.perform(MockMvcRequestBuilders.get("/designer/mock"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("class=\"wt-segment is-active\"")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("aria-selected=\"true\"")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("class=\"wt-segment\"")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("aria-selected=\"false\"")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.RULE_DESIGNER_NAME})
	public void testGetLangDesignerBad() throws Exception {
		BDDMockito.when(mockDesignerService.getDefaultDesignerModelAndView(BDDMockito.anyString()))
				.thenThrow(new ModuleNotFoundException(""));

		mockMvc.perform(MockMvcRequestBuilders.get("/designer/mock"))
				.andExpect(MockMvcResultMatchers.redirectedUrl("/designer"))
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Unknown")));
	}


}
