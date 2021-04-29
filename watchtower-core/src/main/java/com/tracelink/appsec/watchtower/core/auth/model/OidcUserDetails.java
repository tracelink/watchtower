package com.tracelink.appsec.watchtower.core.auth.model;

import java.util.Collection;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/**
 * This class is created to address the fact that the {@link UserDetails} and the {@link OidcUser}
 * classes do not share any of the same methods. When login via OpenID Connect is enabled and you
 * try to access the username of the current principal to display in the top navigation bar, the
 * app does not know whether the user is an {@link UserDetails} or an {@link OidcUser}, and cannot
 * choose the appropriate method to call.
 * <p>
 * By creating this class, which extends {@link User} (and thus implements {@link UserDetails})
 * and implements {@link OidcUser}, we can be sure that the principal always has the method {@link
 * UserDetails#getUsername()}.
 *
 * @author mcool
 */
public class OidcUserDetails extends User implements OidcUser {

	private static final long serialVersionUID = -1376398448243680223L;
	private final OidcUser oidcUser;

	/**
	 * Constructs an instance of this {@link OidcUserDetails} given an {@link OidcUser} and a
	 * collection of granted authorities.
	 *
	 * @param oidcUser    the OIDC user returned upon successful authentication via OIDC
	 * @param authorities authorities locally assigned to this user
	 */
	public OidcUserDetails(OidcUser oidcUser, Collection<GrantedAuthority> authorities) {
		super(oidcUser.getEmail(), "", authorities);
		this.oidcUser = oidcUser;
	}


	@Override
	public Map<String, Object> getClaims() {
		return oidcUser.getClaims();
	}

	@Override
	public OidcUserInfo getUserInfo() {
		return oidcUser.getUserInfo();
	}

	@Override
	public OidcIdToken getIdToken() {
		return oidcUser.getIdToken();
	}

	@Override
	public Map<String, Object> getAttributes() {
		return oidcUser.getAttributes();
	}

	@Override
	public String getName() {
		return getUsername();
	}
}
