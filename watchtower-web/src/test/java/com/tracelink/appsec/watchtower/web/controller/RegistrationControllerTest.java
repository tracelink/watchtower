package com.tracelink.appsec.watchtower.web.controller;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.dao.DataIntegrityViolationException;

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

	@MockitoBean
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
		BDDMockito.verify(mockUserService, BDDMockito.never())
				.registerNewUser(BDDMockito.anyString(), BDDMockito.anyString());
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
		BDDMockito.verify(mockUserService, BDDMockito.never())
				.registerNewUser(BDDMockito.anyString(), BDDMockito.anyString());
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

	@Test
	public void testConcurrentDuplicateRegistrationReturnsValidationError() throws Exception {
		BDDMockito.when(mockUserService.findByUsername(BDDMockito.anyString())).thenReturn(null);
		BDDMockito.doThrow(new DataIntegrityViolationException("duplicate"))
				.when(mockUserService).registerNewUser("csmith", "pw");

		mockMvc.perform(MockMvcRequestBuilders.post("/register").param("username", "csmith")
				.param("password", "pw").param("passwordConfirmation", "pw")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.view().name(Matchers.is("register")))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("already exists")));
	}
}
