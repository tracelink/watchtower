package com.tracelink.appsec.watchtower.core.auth.service;

import java.security.KeyException;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.auth.model.ApiKeyEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.repository.ApiKeyRepository;
import com.tracelink.appsec.watchtower.core.auth.repository.RoleRepository;
import com.tracelink.appsec.watchtower.core.auth.repository.UserRepository;

@ExtendWith(SpringExtension.class)
public class ApiUserServiceTest {

	@MockBean
	private ApiKeyRepository mockApiKeyRepository;

	@MockBean
	private UserService mockUserService;

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	@MockBean
	private UserRepository mockUserRepository;

	@MockBean
	private RoleRepository mockRoleRepository;

	private ApiUserService apiUserService;

	@BeforeEach
	public void setup() {
		this.apiUserService =
				new ApiUserService(mockApiKeyRepository, mockUserService, passwordEncoder);
	}

	@Test
	public void testLoadUserByUsername() {
		String name = "user";
		String secret = "secret";
		ApiKeyEntity apiKey = new ApiKeyEntity();
		UserEntity user = new UserEntity();
		user.setUsername(name);
		apiKey.setSecret(secret);
		apiKey.setUser(user);
		BDDMockito.when(mockApiKeyRepository.findByApiKeyId(BDDMockito.anyString()))
				.thenReturn(apiKey);
		apiUserService.loadUserByUsername("");
		ArgumentCaptor<UserEntity> userCaptor = ArgumentCaptor.forClass(UserEntity.class);
		ArgumentCaptor<String> usernameCaptor = ArgumentCaptor.forClass(String.class);
		ArgumentCaptor<String> secretCaptor = ArgumentCaptor.forClass(String.class);
		BDDMockito.verify(mockUserService).buildUser(usernameCaptor.capture(),
				secretCaptor.capture(), userCaptor.capture());

		MatcherAssert.assertThat(usernameCaptor.getValue(), Matchers.is(name));
		MatcherAssert.assertThat(secretCaptor.getValue(), Matchers.is(secret));
		MatcherAssert.assertThat(userCaptor.getValue(), Matchers.is(user));
	}

	@Test
	public void testLoadUserByUsernameFail() {
		try {
			apiUserService.loadUserByUsername("");
			Assertions.fail("Should throw exception");
		} catch (UsernameNotFoundException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.is("Unknown Api Key"));
		}
	}

	@Test
	public void testCreateNewApiKey() {
		UserEntity user = new UserEntity();
		String label = "label";
		BDDMockito.when(mockApiKeyRepository.saveAndFlush(BDDMockito.any()))
				.then(e -> e.getArgument(0));
		ApiKeyEntity apiKey = apiUserService.createNewApiKey(label, user);
		MatcherAssert.assertThat(apiKey.getUser(), Matchers.is(user));
		MatcherAssert.assertThat(apiKey.getKeyLabel(), Matchers.is(label));
	}

	@Test
	public void testDeleteApiKey() throws KeyException {
		UserEntity user = new UserEntity();
		String apiKeyId = "keyId";

		ApiKeyEntity apiKey = new ApiKeyEntity();
		apiKey.setApiKeyId(apiKeyId);
		user.getApiKeys().add(apiKey);

		apiUserService.deleteApiKey(apiKeyId, user);
		MatcherAssert.assertThat(user.getApiKeys(), Matchers.not(Matchers.contains(apiKey)));
		BDDMockito.verify(mockApiKeyRepository).delete(apiKey);
	}


	@Test
	public void testDeleteApiKeyException() throws KeyException {
		UserEntity user = new UserEntity();
		String apiKeyId = "keyId";

		ApiKeyEntity apiKey = new ApiKeyEntity();
		apiKey.setApiKeyId("DIFFERENT");
		user.getApiKeys().add(apiKey);
		try {
			apiUserService.deleteApiKey(apiKeyId, user);
			Assertions.fail("Should throw exception");
		} catch (KeyException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.is("Key ID does not match User API Key"));
		}
	}
}
