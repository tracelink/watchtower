package com.tracelink.appsec.watchtower.core.logging;

import ch.qos.logback.classic.pattern.MessageConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

/**
 * {@code %msg} with {@link SecretMasker} applied. Registered in {@code logback-spring.xml} under
 * the built-in words, so every appender and the in-app log viewer use it.
 *
 * @author Watchtower
 */
public class MaskingMessageConverter extends MessageConverter {

	@Override
	public String convert(ILoggingEvent event) {
		return SecretMasker.mask(super.convert(event));
	}
}
