package com.tracelink.appsec.watchtower.core.logging;

import ch.qos.logback.classic.pattern.ExtendedThrowableProxyConverter;
import ch.qos.logback.classic.spi.ILoggingEvent;

/**
 * Stack traces with {@link SecretMasker} applied: exception messages (e.g. a parser quoting its
 * input) are where a secret is most likely to reach a log by accident. Registered in
 * {@code logback-spring.xml} under the built-in throwable words ({@code %xEx} etc.).
 *
 * @author Watchtower
 */
public class MaskingThrowableConverter extends ExtendedThrowableProxyConverter {

	@Override
	public String convert(ILoggingEvent event) {
		return SecretMasker.mask(super.convert(event));
	}
}
