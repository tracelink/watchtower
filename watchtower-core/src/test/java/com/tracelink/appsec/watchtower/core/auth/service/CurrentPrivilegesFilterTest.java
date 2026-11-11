package com.tracelink.appsec.watchtower.core.auth.service;

import java.time.Duration;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;
import org.mockito.Mockito;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;

import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;

public class CurrentPrivilegesFilterTest {

	private final UserService userService = Mockito.mock(UserService.class);

	@AfterEach
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	private static UserEntity stored(int enabled, String... privileges) {
		RoleEntity role = new RoleEntity();
		role.setRoleName("role");
		role.setPrivileges(Set.of(privileges).stream()
				.map(name -> new PrivilegeEntity().setName(name))
				.collect(java.util.stream.Collectors.toSet()));
		UserEntity user = new UserEntity();
		user.setUsername("ana");
		user.setEnabled(enabled);
		user.setRoles(Set.of(role));
		return user;
	}

	private static Authentication signedInWith(String... privileges) {
		var authorities = java.util.Arrays.stream(privileges).map(SimpleGrantedAuthority::new)
				.toList();
		var principal = new User("ana", "", authorities);
		var token = UsernamePasswordAuthenticationToken.authenticated(principal, "", authorities);
		SecurityContextHolder.getContext().setAuthentication(token);
		return token;
	}

	private void run(CurrentPrivilegesFilter filter, MockHttpServletRequest request)
			throws Exception {
		filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
	}

	@Test
	public void aRevokedPrivilegeStopsWorkingInAnOpenSession() throws Exception {
		BDDMockito.when(userService.findByUsername("ana")).thenReturn(stored(1, "View"));
		signedInWith("View", "Admin");

		run(new CurrentPrivilegesFilter(userService, Duration.ZERO), new MockHttpServletRequest());

		Assertions.assertEquals(List.of("View"), SecurityContextHolder.getContext()
				.getAuthentication().getAuthorities().stream().map(a -> a.getAuthority()).toList());
	}

	@Test
	public void aNewlyGrantedPrivilegeAppearsWithoutSigningInAgain() throws Exception {
		BDDMockito.when(userService.findByUsername("ana")).thenReturn(stored(1, "View", "Admin"));
		signedInWith("View");

		run(new CurrentPrivilegesFilter(userService, Duration.ZERO), new MockHttpServletRequest());

		Assertions.assertEquals(Set.of("View", "Admin"), SecurityContextHolder.getContext()
				.getAuthentication().getAuthorities().stream().map(a -> a.getAuthority())
				.collect(java.util.stream.Collectors.toSet()));
	}

	@Test
	public void unchangedPrivilegesLeaveTheSignInAlone() throws Exception {
		BDDMockito.when(userService.findByUsername("ana")).thenReturn(stored(1, "View"));
		Authentication before = signedInWith("View");

		run(new CurrentPrivilegesFilter(userService, Duration.ZERO), new MockHttpServletRequest());

		Assertions.assertSame(before, SecurityContextHolder.getContext().getAuthentication());
	}

	@Test
	public void aDisabledUserIsSignedOutAndTheSessionEnds() throws Exception {
		BDDMockito.when(userService.findByUsername("ana")).thenReturn(stored(0, "View"));
		signedInWith("View");
		MockHttpServletRequest request = new MockHttpServletRequest();
		var session = request.getSession(true);

		run(new CurrentPrivilegesFilter(userService, Duration.ZERO), request);

		Assertions.assertNull(SecurityContextHolder.getContext().getAuthentication());
		Assertions.assertTrue(((org.springframework.mock.web.MockHttpSession) session).isInvalid());
	}

	@Test
	public void aUserTheDatabaseDoesNotKnowIsLeftAsSignedIn() throws Exception {
		BDDMockito.when(userService.findByUsername("ana")).thenReturn(null);
		Authentication before = signedInWith("View");

		run(new CurrentPrivilegesFilter(userService, Duration.ZERO), new MockHttpServletRequest());

		Assertions.assertSame(before, SecurityContextHolder.getContext().getAuthentication());
	}

	@Test
	public void privilegesAreReadOncePerCachePeriod() throws Exception {
		BDDMockito.when(userService.findByUsername("ana")).thenReturn(stored(1, "View"));
		CurrentPrivilegesFilter filter = new CurrentPrivilegesFilter(userService,
				Duration.ofHours(1));

		signedInWith("View");
		run(filter, new MockHttpServletRequest());
		signedInWith("View");
		run(filter, new MockHttpServletRequest());

		BDDMockito.verify(userService, Mockito.times(1)).findByUsername("ana");
	}

	@Test
	public void anonymousRequestsAreNotLookedUp() throws Exception {
		run(new CurrentPrivilegesFilter(userService, Duration.ZERO), new MockHttpServletRequest());

		BDDMockito.verifyNoInteractions(userService);
	}
}
