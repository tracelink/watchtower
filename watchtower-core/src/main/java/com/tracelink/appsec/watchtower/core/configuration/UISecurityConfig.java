package com.tracelink.appsec.watchtower.core.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
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
@EnableGlobalMethodSecurity(prePostEnabled = true)
@Order(2)
public class UISecurityConfig extends SecurityConfig {

	private final UserService userService;
	private final OidcAuthService oidcAuthService;

	private final ClientRegistrationRepository clientRegistrationRepository;

	public UISecurityConfig(@Autowired UserService userService,
			@Autowired OidcAuthService oidcAuthService,
			@Autowired(
					required = false) ClientRegistrationRepository clientRegistrationRepository) {
		this.userService = userService;
		this.oidcAuthService = oidcAuthService;
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	/**
	 * Enforce authenticated access to special endpoints. Set up login and logout
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterAfter(new ContentSecurityPolicyFilter(), CsrfFilter.class);
		http.csrf().ignoringAntMatchers("/console/**");
		http.headers().httpStrictTransportSecurity().disable();
		http.headers().frameOptions().disable();
		http
				.authorizeRequests()
				.antMatchers("/error").permitAll()
				.antMatchers("/login").permitAll()
				.antMatchers("/register").permitAll()
				.antMatchers("/console/**").hasAuthority(CorePrivilege.DB_ACCESS_NAME)
				.anyRequest().authenticated()
				.and()
				.formLogin()
				.loginPage("/login")
				.failureHandler(watchtowerAuthFailureHandler())
				.usernameParameter("username")
				.passwordParameter("password")
				.defaultSuccessUrl("/", true)
				.and()
				.logout()
				.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
				.logoutSuccessUrl("/login?logout=true")
				.deleteCookies("JSESSIONID")
				.invalidateHttpSession(true);

		if (clientRegistrationRepository != null
				&& clientRegistrationRepository.findByRegistrationId("oidc") != null) {
			http
					.oauth2Login()
					.loginPage("/login")
					.failureHandler(watchtowerAuthFailureHandler())
					.defaultSuccessUrl("/", true)
					.userInfoEndpoint()
					.oidcUserService(oidcAuthService);
		}
	}

	/**
	 * Configure the correct authentication service for these paths
	 * 
	 * {@inheritDoc}
	 */
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userService);
	}

	/**
	 * Allow all static urls
	 */
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/styles/**", "/icons/**", "/images/**", "/scripts/**",
				"/webjars/**");
	}

	@Bean
	public AuthenticationFailureHandler watchtowerAuthFailureHandler() {
		return new WatchtowerAuthFailureHandler();
	}

}
