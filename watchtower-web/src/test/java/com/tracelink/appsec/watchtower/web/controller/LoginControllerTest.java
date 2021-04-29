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
				.andExpect(MockMvcResultMatchers.view().name(Matchers.is("login")));
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
		LoginController loginController = new LoginController(clientRegistrationRepository);
		Assertions.assertEquals("login-sso", loginController.login());
	}

}
