package com.tracelink.appsec.watchtower.core.configuration;

import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.stereotype.Component;

/**
 * Base Security Config for handling login
 *
 * @author csmith
 */
@Component
public abstract class SecurityConfig extends WebSecurityConfigurerAdapter {

}
