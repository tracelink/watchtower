package com.tracelink.appsec.watchtower.core.configuration;

import com.tracelink.appsec.watchtower.core.auth.service.ApiUserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

/**
 * Security Config for endpoints under /rest/*.
 * <p>
 * Ensures that basic auth is useable in rest, but default does not require authentication.
 * Individual Controllers must use {@linkplain PreAuthorize} to setup authorization rules
 *
 * @author csmith
 */
@EnableWebSecurity
@Configuration
public class RestSecurityConfig {

	private final ApiUserService restAuthService;

	private final PasswordEncoder passwordEncoder;

	public RestSecurityConfig(@Autowired ApiUserService restAuthService,
			@Autowired PasswordEncoder passwordEncoder) {
		this.restAuthService = restAuthService;
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * Restrict all urls under the /rest/ uri to require a user with the API role
	 */
	@Bean
	@Order(1)
	public SecurityFilterChain restSecurityFilterChain(HttpSecurity http) throws Exception {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(restAuthService);
		authProvider.setPasswordEncoder(passwordEncoder);

		http
				.securityMatcher("/rest/**")
				// A browser session also authenticates here (the dashboards read /rest/metrics), so
				// CSRF stays on for it. It is skipped only where a cross-site page cannot act: a
				// request that carries its own Basic credentials (a form cannot set that header),
				// the HMAC-signed webhook and the CSP report endpoint.
				.csrf(csrf -> csrf
						.ignoringRequestMatchers("/rest/scan/**", "/rest/csp/report")
						.ignoringRequestMatchers(RestSecurityConfig::carriesBasicCredentials))
				.authenticationProvider(authProvider)
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/rest/scan/**", "/rest/csp/report").permitAll()
						.anyRequest().authenticated())
				.httpBasic(basic -> basic.authenticationEntryPoint(authEntryPoint()));
		return http.build();
	}

	private static boolean carriesBasicCredentials(HttpServletRequest request) {
		String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
		return authorization != null && authorization.regionMatches(true, 0, "Basic ", 0, 6);
	}

	/**
	 * By forcing this {@linkplain AuthenticationEntryPoint}, we can give the correct 401 response
	 * for basic auth requests. Otherwise, we would fall into the {@linkplain UISecurityConfig}'s
	 * catch-all and end up on "/"
	 *
	 * @return a basic auth entry point
	 */
	private AuthenticationEntryPoint authEntryPoint() {
		BasicAuthenticationEntryPoint basic = new BasicAuthenticationEntryPoint();
		basic.setRealmName("Realm");
		return basic;
	}
}
