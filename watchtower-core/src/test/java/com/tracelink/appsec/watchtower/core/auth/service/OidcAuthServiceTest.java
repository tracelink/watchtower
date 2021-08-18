package com.tracelink.appsec.watchtower.core.auth.service;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.auth.model.OidcUserDetails;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;

@ExtendWith(SpringExtension.class)
public class OidcAuthServiceTest {

	@MockBean
	private UserService userService;

	@MockBean
	private RoleService roleService;

	@Mock
	OidcUserRequest oidcUserRequest;

	private OidcAuthService oidcAuthService;
	private final String sub = UUID.randomUUID().toString();
	private final String email = "jdoe@example.com";
	private OidcIdToken idToken;
	private Map<String, Object> claims;

	@BeforeEach
	public void setup() {
		oidcAuthService = new OidcAuthService(userService, roleService);
		ClientRegistration clientRegistration = ClientRegistration.withRegistrationId("oidc")
				.clientId("ssoServer")
				.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
				.authorizationUri("https://example.com/auth")
				.tokenUri("https://example.com/token")
				.userInfoUri("https://example.com/userinfo")
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).build();

		OAuth2AccessToken accessToken = new OAuth2AccessToken(TokenType.BEARER, "1234567890ABCDEF",
				Instant.now().minusSeconds(10), Instant.now().plusSeconds(10));

		claims = new HashMap<>();
		claims.put("sub", sub);
		claims.put("email", email);
		idToken = new OidcIdToken("1234567890ABCDEF", Instant.now().minusSeconds(10),
				Instant.now().plusSeconds(10), claims);

		BDDMockito.when(oidcUserRequest.getClientRegistration()).thenReturn(clientRegistration);
		BDDMockito.when(oidcUserRequest.getAccessToken()).thenReturn(accessToken);
		BDDMockito.when(oidcUserRequest.getIdToken()).thenReturn(idToken);
	}

	@Test
	public void testLoadUser() {
		RoleEntity role = new RoleEntity();
		String roleName = "foobar";
		role.setRoleName(roleName);
		BDDMockito.when(roleService.findDefaultRole()).thenReturn(role);
		OidcUser oidcUser = oidcAuthService.loadUser(oidcUserRequest);

		ArgumentCaptor<UserEntity> userCaptor = ArgumentCaptor.forClass(UserEntity.class);
		BDDMockito.verify(userService, Mockito.times(1)).updateUser(userCaptor.capture());

		Assertions.assertEquals(sub, userCaptor.getValue().getSsoId());
		Assertions.assertTrue(userCaptor.getValue().isSsoUser());
		Assertions.assertEquals(email, userCaptor.getValue().getUsername());
		Assertions.assertEquals(1, userCaptor.getValue().getRoles().size());
		Assertions.assertTrue(userCaptor.getValue().getRoles().contains(role));
		Assertions.assertEquals(1, userCaptor.getValue().getEnabled());
		Assertions.assertNull(userCaptor.getValue().getPassword());

		Assertions.assertTrue(oidcUser instanceof OidcUserDetails);
		Assertions.assertEquals(email, oidcUser.getName());
		Assertions.assertEquals(1, oidcUser.getAuthorities().size());
		Assertions.assertEquals(roleName,
				oidcUser.getAuthorities().iterator().next().getAuthority());
		Assertions.assertEquals(claims, oidcUser.getClaims());
		Assertions.assertEquals(idToken, oidcUser.getIdToken());
		Assertions.assertNull(oidcUser.getUserInfo());
		Assertions.assertEquals(claims, oidcUser.getAttributes());

	}

	@Test
	public void testLoadUserExistingLocalUser() {
		UserEntity user = new UserEntity();
		user.setUsername(email);
		user.setSsoId(sub);
		user.setEnabled(1);
		BDDMockito.when(userService.findByUsername(email)).thenReturn(user);
		OidcUser oidcUser = oidcAuthService.loadUser(oidcUserRequest);

		BDDMockito.verify(userService, Mockito.times(0)).updateUser(user);

		Assertions.assertTrue(oidcUser instanceof OidcUserDetails);
		Assertions.assertEquals(email, oidcUser.getName());
		Assertions.assertTrue(oidcUser.getAuthorities().isEmpty());
	}

	@Test
	public void testLoadUserMissingEmail() {
		claims.remove("email");
		claims.put("username", "jdoe");
		idToken = new OidcIdToken("1234567890ABCDEF", Instant.now().minusSeconds(10),
				Instant.now().plusSeconds(10), claims);
		BDDMockito.when(oidcUserRequest.getIdToken()).thenReturn(idToken);

		try {
			oidcAuthService.loadUser(oidcUserRequest);
			Assertions.fail("Exception should have been thrown");
		} catch (OAuth2AuthenticationException e) {
			Assertions.assertTrue(
					e.getMessage().contains("User info must contain an email attribute to login."));
		}
	}

	@Test
	public void testLoadUserExistingLocalUserCollision() {
		UserEntity user = new UserEntity();
		user.setUsername(email);
		BDDMockito.when(userService.findByUsername(email)).thenReturn(user);
		try {
			oidcAuthService.loadUser(oidcUserRequest);
			Assertions.fail("Exception should have been thrown");
		} catch (OAuth2AuthenticationException e) {
			Assertions.assertTrue(e.getMessage()
					.contains("A local user with the username \"" + email + "\" already exists."));
		}

		BDDMockito.verify(userService, Mockito.times(0)).updateUser(user);
	}

	@Test
	public void testLoadUserExistingSsoUser() {
		UserEntity user = new UserEntity();
		user.setUsername("oldemail@example.com");
		user.setSsoId(sub);
		user.setEnabled(1);
		BDDMockito.when(userService.findByUsername(email)).thenReturn(null);
		BDDMockito.when(userService.findBySsoId(sub)).thenReturn(user);
		oidcAuthService.loadUser(oidcUserRequest);

		BDDMockito.verify(userService, Mockito.times(1)).updateUser(user);
		Assertions.assertEquals(email, user.getUsername());
	}

	@Test
	public void testLoadUserExistingDisabledSsoUser() {
		UserEntity user = new UserEntity();
		user.setUsername("oldemail@example.com");
		user.setSsoId(sub);
		user.setEnabled(0);
		BDDMockito.when(userService.findByUsername(email)).thenReturn(null);
		BDDMockito.when(userService.findBySsoId(sub)).thenReturn(user);

		try {
			oidcAuthService.loadUser(oidcUserRequest);
			Assertions.fail("Exception should have been thrown");
		} catch (DisabledException e) {
			Assertions.assertEquals("Account disabled", e.getMessage());
		}

		BDDMockito.verify(userService, Mockito.times(1)).updateUser(user);
		Assertions.assertEquals(email, user.getUsername());
	}

	@Test
	public void testLoadUserExistingSsoUserWithRoles() {
		UserEntity user = new UserEntity();
		user.setUsername("oldemail@example.com");
		user.setSsoId(sub);
		user.setEnabled(1);

		RoleEntity role = new RoleEntity();
		role.setRoleName("SpecialRole");
		user.setRoles(Collections.singleton(role));

		BDDMockito.when(userService.findByUsername(email)).thenReturn(null);
		BDDMockito.when(userService.findBySsoId(sub)).thenReturn(user);
		OidcUser oidcUser = oidcAuthService.loadUser(oidcUserRequest);

		BDDMockito.verify(userService, Mockito.times(1)).updateUser(user);
		Assertions.assertEquals(email, user.getUsername());

		Assertions.assertEquals(1, oidcUser.getAuthorities().size());
		Assertions.assertEquals(role.getRoleName(),
				oidcUser.getAuthorities().iterator().next().getAuthority());
	}
}
