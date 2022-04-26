package com.tracelink.appsec.watchtower.core.auth.controller;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.ApiKeyEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.ApiUserService;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import java.security.KeyException;
import java.util.Date;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class ProfileControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	private UserService mockUserService;

	@MockBean
	private ApiUserService mockApiService;

	///////////////////
	// Get profile
	///////////////////
	@Test
	@WithMockUser
	public void testGetProfileAdmin() throws Exception {
		String username = getContextPrincipalName();
		Date join = new Date();

		UserEntity user = BDDMockito.mock(UserEntity.class);
		BDDMockito.when(user.getCreated()).thenReturn(join);
		BDDMockito.when(user.getUsername()).thenReturn(username);
		BDDMockito.when(mockUserService.findByUsername(BDDMockito.anyString())).thenReturn(user);

		mockMvc.perform(MockMvcRequestBuilders.get("/profile"))
				.andExpect(
						MockMvcResultMatchers.model().attribute("user_name", Matchers.is(username)))
				.andExpect(MockMvcResultMatchers.model().attribute("join_date", Matchers.is(join)));
	}

	///////////////////
	// Post profile
	///////////////////

	@Test
	@WithMockUser
	public void testChangePasswordFail() throws Exception {
		String currentPassword = "pass";
		String newPassword = "newpass";

		UserEntity user = BDDMockito.mock(UserEntity.class);
		BDDMockito.when(user.getSsoId()).thenReturn("abcdef1234567890");

		BDDMockito.when(mockUserService.findByUsername(BDDMockito.anyString()))
				.thenReturn(user);
		BDDMockito.willThrow(UsernameNotFoundException.class).given(mockUserService).changePassword(
				BDDMockito.anyString(), BDDMockito.anyString(), BDDMockito.anyString());

		mockMvc.perform(
				MockMvcRequestBuilders.post("/profile/changePassword")
						.param("currentPassword", currentPassword)
						.param("newPassword", newPassword)
						.param("confirmPassword", newPassword)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(
						MockMvcResultMatchers.flash()
								.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
										Matchers.anything()));
	}

	@Test
	@WithMockUser
	public void testChangeProfilePasswordMismatch() throws Exception {
		String current = "pw";
		String newPw = "newpw";

		UserEntity user = BDDMockito.mock(UserEntity.class);
		BDDMockito.when(mockUserService.findByUsername(BDDMockito.anyString())).thenReturn(user);

		mockMvc.perform(
				MockMvcRequestBuilders.post("/profile/changePassword")
						.param("currentPassword", current)
						.param("newPassword", newPw)
						.param("confirmPassword", "INCORRECT")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.is("Your provided passwords don't match")));
	}


	@Test
	@WithMockUser
	public void testChangeProfileSuccess() throws Exception {
		String current = "pw";
		String newPw = "newpw";

		UserEntity user = BDDMockito.mock(UserEntity.class);
		BDDMockito.when(mockUserService.findByUsername(BDDMockito.anyString())).thenReturn(user);
		BDDMockito
				.when(mockUserService.checkPassword(BDDMockito.any(UserEntity.class),
						BDDMockito.anyString()))
				.thenReturn(true);

		mockMvc.perform(
				MockMvcRequestBuilders.post("/profile/changePassword")
						.param("currentPassword", current)
						.param("newPassword", newPw)
						.param("confirmPassword", newPw)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								Matchers.is("Your password has been updated successfully.")));
	}

	@Test
	@WithMockUser
	public void testCreateApiKey() throws Exception {
		String apiKeyLabel = "keyName";

		UserEntity user = BDDMockito.mock(UserEntity.class);
		BDDMockito.when(mockUserService.findByUsername(BDDMockito.anyString())).thenReturn(user);

		ApiKeyEntity apiKey = BDDMockito.mock(ApiKeyEntity.class);
		BDDMockito
				.when(mockApiService.createUserApiKey(apiKeyLabel, user)).thenReturn(apiKey);

		mockMvc.perform(
				MockMvcRequestBuilders.post("/profile/apikey/create")
						.param("apiKeyLabel", apiKeyLabel)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								Matchers.containsString("Created Key ID")));
	}

	@Test
	@WithMockUser
	public void testDeleteApiKeySuccess() throws Exception {
		String apiKeyId = "apiKeyId";

		UserEntity user = BDDMockito.mock(UserEntity.class);
		BDDMockito.when(mockUserService.findByUsername(BDDMockito.anyString())).thenReturn(user);

		mockMvc.perform(
				MockMvcRequestBuilders.post("/profile/apikey/delete")
						.param("apiKeyId", apiKeyId)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								Matchers.containsString("Successfully deleted key")));
	}

	@Test
	@WithMockUser
	public void testDeleteApiKeyFail() throws Exception {
		String apiKeyId = "apiKeyId";

		UserEntity user = BDDMockito.mock(UserEntity.class);
		BDDMockito.when(mockUserService.findByUsername(BDDMockito.anyString())).thenReturn(user);
		BDDMockito.willThrow(KeyException.class).given(mockApiService)
				.deleteUserApiKey(apiKeyId, user);

		mockMvc.perform(
				MockMvcRequestBuilders.post("/profile/apikey/delete")
						.param("apiKeyId", apiKeyId)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.anything()));
	}

	private String getContextPrincipalName() {
		org.springframework.security.core.userdetails.User principal =
				(org.springframework.security.core.userdetails.User) SecurityContextHolder
						.getContext().getAuthentication().getPrincipal();
		return principal.getUsername();
	}
}
