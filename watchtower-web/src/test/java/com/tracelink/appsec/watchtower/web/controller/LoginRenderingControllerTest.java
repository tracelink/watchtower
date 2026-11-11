package com.tracelink.appsec.watchtower.web.controller;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class LoginRenderingControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void loginWithErrorRendersAccessibleFieldsInRestrictedExpressionMode() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/login")
				.param("error", "Invalid username or password."))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.content().string(
						org.hamcrest.Matchers.containsString("aria-describedby=\"login-error\"")))
				.andExpect(MockMvcResultMatchers.content().string(
						org.hamcrest.Matchers.containsString("aria-invalid=\"true\"")));
	}
}
