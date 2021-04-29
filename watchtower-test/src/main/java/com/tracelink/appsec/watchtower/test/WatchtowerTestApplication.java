package com.tracelink.appsec.watchtower.test;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * A Test Watchtower implementation to handle Modules needing to start Watchtower for controller
 * testing
 * 
 * @author csmith
 *
 */
@SpringBootApplication(scanBasePackages = "com.tracelink.appsec.watchtower")
@EntityScan(basePackages = "com.tracelink.appsec.watchtower")
@EnableJpaRepositories(basePackages = "com.tracelink.appsec.watchtower")
public class WatchtowerTestApplication {
}
