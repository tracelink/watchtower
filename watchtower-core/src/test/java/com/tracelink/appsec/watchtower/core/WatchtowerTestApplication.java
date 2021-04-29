package com.tracelink.appsec.watchtower.core;

import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.encoder.PatternLayoutEncoder;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.encoder.LayoutWrappingEncoder;
import ch.qos.logback.core.read.CyclicBufferAppender;

@SpringBootApplication(scanBasePackages = "com.tracelink.appsec.watchtower")
@EntityScan(basePackages = "com.tracelink.appsec.watchtower")
@EnableJpaRepositories(basePackages = "com.tracelink.appsec.watchtower")
public class WatchtowerTestApplication {
	private static final String APPENDER_NAME = "ROLLING-QUEUE";
	private static final String PATTERN_LAYOUT = "%msg%n";

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}

	@Bean
	public Logger appLogger() {
		LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
		return context.getLogger("com.tracelink.appsec");
	}

	@Bean
	public CyclicBufferAppender<ILoggingEvent> appender() {
		return (CyclicBufferAppender<ILoggingEvent>) appLogger().getAppender(APPENDER_NAME);
	}

	@Bean
	public LayoutWrappingEncoder<ILoggingEvent> encoder() {
		PatternLayoutEncoder encoder = new PatternLayoutEncoder();
		encoder.setContext(appLogger().getLoggerContext());
		encoder.setPattern(PATTERN_LAYOUT);
		encoder.start();
		return encoder;
	}

	@Configuration
	@EnableWebSecurity
	@EnableGlobalMethodSecurity(prePostEnabled = true)
	static class WatchtowerTestConfiguration extends WebSecurityConfigurerAdapter {

	}
}
