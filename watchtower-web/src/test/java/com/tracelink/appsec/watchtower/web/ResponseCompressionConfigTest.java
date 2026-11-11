package com.tracelink.appsec.watchtower.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.io.ClassPathResource;

/** Large reports are sent compressed: a 224-finding report is about 500 KB of HTML. */
class ResponseCompressionConfigTest {

	@Test
	void htmlAndJsonAreCompressedAboveASmallSize() {
		YamlPropertiesFactoryBean yaml = new YamlPropertiesFactoryBean();
		yaml.setResources(new ClassPathResource("application.yaml"));

		var properties = yaml.getObject();

		assertEquals("true", properties.getProperty("server.compression.enabled"));
		assertTrue(properties.getProperty("server.compression.mime-types").contains("text/html"));
		assertTrue(properties.getProperty("server.compression.mime-types").contains("application/json"));
		assertEquals("2KB", properties.getProperty("server.compression.min-response-size"));
	}
}
