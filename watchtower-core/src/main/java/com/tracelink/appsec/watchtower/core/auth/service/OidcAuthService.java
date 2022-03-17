package com.tracelink.appsec.watchtower.core.auth.service;

import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.auth.model.OidcUserDetails;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;

/**
 * Service to store and retrieve users in the database, if they login via OpenID Connect. When users
 * login for the first time, this service will create a new {@link UserEntity} in the database to
 * keep track of user roles and privileges.
 * <p>
 * Note that this service does not attempt to link an SSO user to a local user if they have the same
 * username. If there is a username collision, the SSO user cannot login.
 *
 * @author mcool
 */
@Service
public class OidcAuthService extends OidcUserService {

	private static final Logger LOGGER = LoggerFactory.getLogger(OidcAuthService.class);

	private final UserService userService;

	private final RoleService roleService;

	/**
	 * Constructor for this service that configures a {@link UserService} and {@link RoleService}
	 * for interaction with the user database.
	 *
	 * @param userService to store and retrieve {@link UserEntity} objects.
	 * @param roleService to store and retrieve {@link RoleEntity} objects.
	 */
	public OidcAuthService(@Autowired UserService userService, @Autowired RoleService roleService) {
		this.userService = userService;
		this.roleService = roleService;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public OidcUser loadUser(OidcUserRequest userRequest)
			throws OAuth2AuthenticationException {
		OidcUser oidcUser = super.loadUser(userRequest);

		// Check that the user info contains an email
		String username = oidcUser.getEmail();
		if (username == null) {
			OAuth2Error oAuth2Error = new OAuth2Error("missing_user_email_attribute");
			throw new OAuth2AuthenticationException(oAuth2Error,
					"User info must contain an email attribute to login.");
		}

		UserEntity user;
		// Check if there is a user in the DB with the same username
		UserEntity localUser = userService.findByUsername(username);
		if (localUser != null) {
			// Check if the local user has the same SSO id
			if (localUser.getSsoId() == null) {
				// There is a username collision, prevent login
				LOGGER.warn("User with username \"" + username
						+ "\" attempted to login via SSO, but already has a local user account.");
				OAuth2Error oauth2Error = new OAuth2Error("username_collision");
				throw new OAuth2AuthenticationException(oauth2Error,
						"A local user with the username \"" + username
								+ "\" already exists. Please login with the provided form instead of SSO.");
			} else {
				user = localUser;
			}
		} else {
			user = userService.findBySsoId(oidcUser.getSubject());
		}

		// This is the first time this user is logging in via SSO
		if (user == null) {
			user = new UserEntity();
			user.setSsoId(oidcUser.getSubject());
			user.setUsername(username);
			user.setEnabled(1);

			RoleEntity userRole = roleService.findDefaultRole();
			user.setRoles(Collections.singleton(userRole));
			user.setCreated(new Date());
			userService.updateUser(user);
		}

		// Update local ssoId if the SSO subject has changed
		if (!user.getSsoId().equals(oidcUser.getSubject())) {
			user.setSsoId(oidcUser.getSubject());
			userService.updateUser(user);
		}

		// Update local username if the user's email has been updated in the SSO
		if (!user.getUsername().equals(username)) {
			user.setUsername(username);
			userService.updateUser(user);
		}

		// If user is disabled, prevent login
		if (user.getEnabled() == 0) {
			throw new DisabledException("Account disabled");
		}

		// Get database roles and privileges
		Collection<GrantedAuthority> authorities =
				user.getRoles()
						.stream().flatMap(r -> r.getPrivileges().stream())
						.map(PrivilegeEntity::getName).map(SimpleGrantedAuthority::new)
						.collect(Collectors.toSet());

		return new OidcUserDetails(oidcUser, authorities);
	}
}
