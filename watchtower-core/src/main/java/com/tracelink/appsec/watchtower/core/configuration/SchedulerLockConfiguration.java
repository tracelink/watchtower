package com.tracelink.appsec.watchtower.core.configuration;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import net.javacrumbs.shedlock.core.LockProvider;
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock;
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock.InterceptMode;

/**
 * Lets a {@code @Scheduled} method marked {@code @SchedulerLock} run on one pod at a time, using
 * the {@code shedlock} table. The scheduler itself is proxied rather than each bean, so the lock
 * also applies to private scheduled methods. Lock times use the database clock, so pods with
 * drifting clocks still agree on when a lock expires.
 *
 * @author Watchtower
 */
@Configuration
@EnableSchedulerLock(interceptMode = InterceptMode.PROXY_SCHEDULER,
		defaultLockAtMostFor = "PT10M")
public class SchedulerLockConfiguration {

	@Bean
	public LockProvider lockProvider(DataSource dataSource) {
		return new JdbcTemplateLockProvider(JdbcTemplateLockProvider.Configuration.builder()
				.withJdbcTemplate(new JdbcTemplate(dataSource))
				.usingDbTime()
				.build());
	}
}
