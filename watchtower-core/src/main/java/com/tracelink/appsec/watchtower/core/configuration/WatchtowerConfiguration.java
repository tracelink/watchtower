package com.tracelink.appsec.watchtower.core.configuration;

import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.tracelink.appsec.watchtower.core.logging.LogsService;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.CyclicBufferAppender;

/**
 * Spring Configuration
 *
 * @author csmith
 */
@Configuration
@EnableScheduling
@EnableAsync
public class WatchtowerConfiguration {
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(12);
	}

	@Bean
	public Logger appLogger() {
		LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
		return context.getLogger(LogsService.LOGGER_NAME);
	}

	@Bean
	public CyclicBufferAppender<ILoggingEvent> cyclicAppender() {
		return (CyclicBufferAppender<ILoggingEvent>) appLogger()
				.getAppender(LogsService.APPENDER_NAME);
	}

}
