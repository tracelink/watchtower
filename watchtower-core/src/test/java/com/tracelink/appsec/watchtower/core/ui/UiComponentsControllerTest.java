package com.tracelink.appsec.watchtower.core.ui;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;

@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
class UiComponentsControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	@WithMockUser(authorities = CorePrivilege.ROLE_VIEW_NAME)
	void roleViewerCanOpenComponentPreview() throws Exception {
		MvcResult result = mockMvc.perform(get("/admin/ui/components"))
				.andExpect(status().isOk())
				.andExpect(model().attribute("contentViewName", "admin/ui-components"))
				.andReturn();

		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = CorePrivilege.USER_VIEW_NAME)
	void userWithoutRoleViewCannotOpenComponentPreview() throws Exception {
		mockMvc.perform(get("/admin/ui/components"))
				.andExpect(status().isForbidden());
	}
}
