package com.tracelink.appsec.watchtower.core.module;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;

/** The Scanner modules page can be seen with View alone; changing anything still needs Modify. */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
class ModuleControlViewAccessTest {
	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private ModuleControlService controls;

	@MockitoBean
	private ScanRegistrationService registry;

	@Test
	@WithMockUser(authorities = "Module Settings View")
	void viewAloneOpensThePageButCannotChangeAModule() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/configuration/modules"))
				.andExpect(MockMvcResultMatchers.status().isOk());
		mockMvc.perform(MockMvcRequestBuilders.post("/configuration/modules")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("module", "regex")
				.param("enabled", "false").param("version", "0"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
		mockMvc.perform(MockMvcRequestBuilders.post("/configuration/modules/file-types")
				.with(SecurityMockMvcRequestPostProcessors.csrf()).param("module", "regex")
				.param("version", "0"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}

	@Test
	@WithMockUser(authorities = "Module Settings Modify")
	void modifyStillOpensThePage() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/configuration/modules"))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.model().attribute("canModify", true));
	}

	@Test
	@WithMockUser(authorities = "Module Settings View")
	void viewOnlyGetsTheControlsSwitchedOff() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/configuration/modules"))
				.andExpect(MockMvcResultMatchers.model().attribute("canModify", false))
				.andExpect(MockMvcResultMatchers.content().string(Matchers.not(Matchers.containsString("Forbidden"))));
	}

	@Test
	@WithMockUser(authorities = "Scan Results View")
	void anyOtherPrivilegeIsRefused() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/configuration/modules"))
				.andExpect(MockMvcResultMatchers.status().isForbidden());
	}
}
