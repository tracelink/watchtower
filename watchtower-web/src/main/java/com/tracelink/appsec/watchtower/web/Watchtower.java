package com.tracelink.appsec.watchtower.web;

import org.springframework.boot.Banner.Mode;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * Main App Starter
 *
 * @author csmith
 */
@SpringBootApplication(scanBasePackages = "com.tracelink.appsec.watchtower")
@EntityScan(basePackages = "com.tracelink.appsec.watchtower")
@EnableJpaRepositories(basePackages = "com.tracelink.appsec.watchtower")
public class Watchtower {
	/**
	 * Main Entry for Watchtower
	 * 
	 * @param args passed-in command line args
	 */
	public static void main(String... args) {
		SpringApplication app = new SpringApplication(Watchtower.class);
		app.setBannerMode(Mode.OFF);
		app.run(args);
	}
}
