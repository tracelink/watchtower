package com.tracelink.appsec.watchtower.web.controller;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
public class RegistrationControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private UserService mockUserService;

	///////////////////
	// Get register
	///////////////////
	@Test
	public void testGetRegister() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/register"))
				.andExpect(MockMvcResultMatchers.view().name(Matchers.is("register")));
	}

	///////////////////
	// Post register
	///////////////////
	@Test
	public void testRegisterUserExists() throws Exception {
		BDDMockito.when(mockUserService.findByUsername(BDDMockito.anyString()))
				.thenReturn(BDDMockito.mock(UserEntity.class));
		String username = "csmith";
		String password = "pw";

		mockMvc.perform(MockMvcRequestBuilders.post("/register").param("username", username)
				.param("password", password)
				.param("passwordConfirmation", password)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.view().name(Matchers.is("register")))
				.andExpect(MockMvcResultMatchers
						.content()
						.string(Matchers.containsString("User with that username already exists")));
	}

	@Test
	public void testRegisterPasswordMismatch() throws Exception {
		BDDMockito.when(mockUserService.findByUsername(BDDMockito.anyString())).thenReturn(null);
		String username = "csmith";
		String password = "pw";

		mockMvc.perform(MockMvcRequestBuilders.post("/register").param("username", username)
				.param("password", password)
				.param("passwordConfirmation", "INCORRECT")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.view().name(Matchers.is("register"))).andExpect(
						MockMvcResultMatchers.content()
								.string(Matchers.containsString("Passwords don&#39;t match")));
	}

	@Test
	public void testRegisterSuccess() throws Exception {
		BDDMockito.when(mockUserService.findByUsername(BDDMockito.anyString())).thenReturn(null);
		String username = "csmith";
		String password = "pw";

		mockMvc.perform(MockMvcRequestBuilders.post("/register").param("username", username)
				.param("password", password)
				.param("passwordConfirmation", password)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								Matchers.containsString("User account created successfully")));
	}
}
