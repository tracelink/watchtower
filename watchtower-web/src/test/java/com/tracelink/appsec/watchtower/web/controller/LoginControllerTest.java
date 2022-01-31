package com.tracelink.appsec.watchtower.web.controller;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.web.servlet.ModelAndView;

@ExtendWith(SpringExtension.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
public class LoginControllerTest {
	@Autowired
	private MockMvc mockMvc;

	///////////////////
	// Get login
	///////////////////
	@Test
	public void testGetLogin() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/login"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.view().name(Matchers.is("login")))
				.andExpect(MockMvcResultMatchers.model().attribute("allowRegistration", true));
	}

	@Test
	public void testGetLoginSso() {
		ClientRegistration clientRegistration =
				ClientRegistration.withRegistrationId("oidc").authorizationGrantType(
						AuthorizationGrantType.PASSWORD).clientId("foo").tokenUri("/bar").build();
		ClientRegistrationRepository clientRegistrationRepository =
				BDDMockito.mock(ClientRegistrationRepository.class);
		BDDMockito.when(clientRegistrationRepository.findByRegistrationId("oidc"))
				.thenReturn(clientRegistration);
		LoginController loginController = new LoginController(clientRegistrationRepository, true);
		ModelAndView mav = loginController.login();
		Assertions.assertEquals("login-sso", mav.getViewName());
	}

	@Test
	public void testGetLoginNoRegister() {
		LoginController loginController = new LoginController(null, false);
		ModelAndView mav = loginController.login();
		Assertions.assertEquals("login", mav.getViewName());
		Assertions.assertEquals(false, mav.getModel().get("allowRegistration"));
	}

}
