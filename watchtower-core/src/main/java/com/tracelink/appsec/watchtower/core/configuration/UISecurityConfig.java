package com.tracelink.appsec.watchtower.core.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CsrfFilter;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.auth.service.CurrentPrivilegesFilter;
import com.tracelink.appsec.watchtower.core.auth.service.OidcAuthService;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.csp.ContentSecurityPolicyFilter;
import com.tracelink.appsec.watchtower.core.handler.WatchtowerAuthFailureHandler;

/**
 * Security Config for all non-rest endpoints
 *
 * @author csmith
 */
@EnableWebSecurity
@Configuration
@EnableMethodSecurity
public class UISecurityConfig {

	private final UserService userService;
	private final OidcAuthService oidcAuthService;

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final PasswordEncoder passwordEncoder;

	public UISecurityConfig(@Autowired UserService userService,
			@Autowired OidcAuthService oidcAuthService,
			@Autowired(
					required = false) ClientRegistrationRepository clientRegistrationRepository,
			@Autowired PasswordEncoder passwordEncoder) {
		this.userService = userService;
		this.oidcAuthService = oidcAuthService;
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * Enforce authenticated access to special endpoints. Set up login and logout
	 */
	@Bean
	@Order(2)
	public SecurityFilterChain uiSecurityFilterChain(HttpSecurity http) throws Exception {
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userService);
		authProvider.setPasswordEncoder(passwordEncoder);

		http.addFilterAfter(new ContentSecurityPolicyFilter(), CsrfFilter.class);
		http.addFilterAfter(
				new CurrentPrivilegesFilter(userService, CurrentPrivilegesFilter.DEFAULT_TTL),
				SecurityContextHolderFilter.class);
		http.headers(headers -> headers
				.httpStrictTransportSecurity(hsts -> hsts
						.maxAgeInSeconds(31536000)
						.includeSubDomains(true)
						.preload(true))
				.frameOptions(frame -> frame.deny()));
		http
				.authenticationProvider(authProvider)
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/error").permitAll()
						.requestMatchers("/login").permitAll()
						.requestMatchers("/register").permitAll()
						.requestMatchers("/styles/**", "/icons/**", "/images/**", "/scripts/**",
								"/webjars/**", "/fonts/**")
						.permitAll()
						// Actuator (IMPROVEMENT_PLAN.md item 6.0/6.6) is on its own port,
						// bound to 127.0.0.1 and never exposed via the Service/Ingress
						// (see application.yaml's own comments) - that network isolation
						// is the security boundary, the same defense-in-depth reasoning
						// already used for the JDWP debug port in deploy.yaml. Without
						// this, this catch-all chain's anyRequest().authenticated() below
						// applies to actuator requests too (this app has no separate
						// management-context security config), making
						// /actuator/metrics unreachable by anything that can't complete a
						// cookie-based login - e.g. a Prometheus scraper or a plain curl
						// from a kubectl port-forward.
						.requestMatchers("/actuator/**").permitAll()
						.anyRequest().authenticated())
				.formLogin(form -> form
						.loginPage("/login")
						.failureHandler(watchtowerAuthFailureHandler())
						.usernameParameter("username")
						.passwordParameter("password")
						.defaultSuccessUrl("/", true))
				.logout(logout -> logout
						.logoutUrl("/logout")
						.logoutSuccessUrl("/login?logout=true")
						.deleteCookies("JSESSIONID")
						.invalidateHttpSession(true));

		if (clientRegistrationRepository != null
				&& clientRegistrationRepository.findByRegistrationId("oidc") != null) {
			http.oauth2Login(oauth2 -> oauth2
					.loginPage("/login")
					.failureHandler(watchtowerAuthFailureHandler())
					.defaultSuccessUrl("/", true)
					.userInfoEndpoint(userInfo -> userInfo.oidcUserService(oidcAuthService)));
		}

		return http.build();
	}

	@Bean
	public AuthenticationFailureHandler watchtowerAuthFailureHandler() {
		return new WatchtowerAuthFailureHandler();
	}

}
