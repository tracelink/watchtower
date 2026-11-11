package com.tracelink.appsec.watchtower.core.auth.service;

import java.io.IOException;
import java.time.Duration;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;

/**
 * Keeps a signed-in user's privileges current. Spring copies privileges into the session at
 * sign-in, so without this a revoked role would keep working until the session ended. Each
 * request re-reads the user's privileges (cached for a short time, so the database is not hit
 * on every request) and replaces the session's authorities when they changed. A user who was
 * disabled is signed out. A user this filter cannot find is left as the sign-in made them.
 *
 * @author Watchtower
 */
public class CurrentPrivilegesFilter extends OncePerRequestFilter {

	/** How long a user's privileges are trusted before they are read again. */
	public static final Duration DEFAULT_TTL = Duration.ofSeconds(15);

	private record Snapshot(boolean enabled, Set<String> privileges, long loadedAtMillis) {
	}

	private final UserService userService;
	private final long ttlMillis;
	private final Map<String, Snapshot> snapshots = new ConcurrentHashMap<>();

	public CurrentPrivilegesFilter(UserService userService, Duration ttl) {
		this.userService = userService;
		this.ttlMillis = ttl.toMillis();
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain chain) throws ServletException, IOException {
		SecurityContext context = SecurityContextHolder.getContext();
		Authentication authentication = context.getAuthentication();
		if (authentication != null && authentication.isAuthenticated()
				&& authentication.getPrincipal() instanceof UserDetails principal) {
			Snapshot current = snapshotOf(principal.getUsername());
			if (current != null && !current.enabled()) {
				snapshots.remove(principal.getUsername());
				SecurityContextHolder.clearContext();
				HttpSession session = request.getSession(false);
				if (session != null) {
					session.invalidate();
				}
			} else if (current != null && !sameAuthorities(authentication, current)) {
				Authentication refreshed = withPrivileges(authentication, current.privileges());
				if (refreshed != null) {
					context.setAuthentication(refreshed);
				}
			}
		}
		chain.doFilter(request, response);
	}

	private Snapshot snapshotOf(String username) {
		if (username == null) {
			return null;
		}
		long now = System.currentTimeMillis();
		Snapshot known = snapshots.get(username);
		if (known != null && now - known.loadedAtMillis() < ttlMillis) {
			return known;
		}
		UserEntity user = userService.findByUsername(username);
		if (user == null) {
			snapshots.remove(username);
			return null;
		}
		Set<String> privileges = user.getRoles().stream().flatMap(r -> r.getPrivileges().stream())
				.map(PrivilegeEntity::getName).collect(Collectors.toUnmodifiableSet());
		Snapshot loaded = new Snapshot(user.getEnabled() != 0, privileges, now);
		snapshots.put(username, loaded);
		return loaded;
	}

	private static boolean sameAuthorities(Authentication authentication, Snapshot current) {
		Set<String> held = authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
		return held.equals(current.privileges());
	}

	private static Authentication withPrivileges(Authentication authentication,
			Set<String> privileges) {
		Collection<GrantedAuthority> authorities = privileges.stream()
				.<GrantedAuthority>map(SimpleGrantedAuthority::new).toList();
		if (authentication instanceof OAuth2AuthenticationToken oauth
				&& oauth.getPrincipal() instanceof OAuth2User user) {
			OAuth2AuthenticationToken token = new OAuth2AuthenticationToken(user, authorities,
					oauth.getAuthorizedClientRegistrationId());
			token.setDetails(oauth.getDetails());
			return token;
		}
		if (authentication instanceof UsernamePasswordAuthenticationToken) {
			UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken
					.authenticated(authentication.getPrincipal(), authentication.getCredentials(),
							authorities);
			token.setDetails(authentication.getDetails());
			return token;
		}
		return null;
	}
}
