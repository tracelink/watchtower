package com.tracelink.appsec.watchtower.core.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationEntryPoint;

import com.tracelink.appsec.watchtower.core.auth.service.ApiUserService;

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
@Order(1)
public class RestSecurityConfig extends SecurityConfig {

	private final ApiUserService restAuthService;

	public RestSecurityConfig(@Autowired ApiUserService restAuthService) {
		this.restAuthService = restAuthService;
	}

	/**
	 * Restrict all urls under the /rest/ uri to require a user with the API role
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().ignoringAntMatchers("/rest/**");

		http
				.antMatcher("/rest/**")
				.authorizeRequests().anyRequest().permitAll()
				.and()
				.httpBasic().authenticationEntryPoint(authEntryPoint());
	}

	/**
	 * Configure the correct authentication service for these paths
	 * 
	 * {@inheritDoc}
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(restAuthService);
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
