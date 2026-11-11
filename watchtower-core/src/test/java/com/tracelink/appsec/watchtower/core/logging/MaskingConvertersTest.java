package com.tracelink.appsec.watchtower.core.logging;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggingEvent;

public class MaskingConvertersTest {

	private static final String GITHUB_PAT = "ghp_" + "Xa9Bc3De5Fg7Hi1Jk3Lm5No7Pq9Rs1Tu3Vw5";

	private static LoggingEvent event(String message, Throwable throwable) {
		LoggerContext context = new LoggerContext();
		return new LoggingEvent("fqcn", context.getLogger("test"), Level.WARN, message, throwable,
				new Object[] {GITHUB_PAT});
	}

	@Test
	public void testTheMessageIsMaskedAfterItsArgumentsAreFilledIn() {
		MaskingMessageConverter converter = new MaskingMessageConverter();

		String line = converter.convert(event("Bad response body: {}", null));

		MatcherAssert.assertThat(line, Matchers.not(Matchers.containsString(GITHUB_PAT)));
		MatcherAssert.assertThat(line, Matchers.containsString("Bad response body: ghp_****"));
	}

	@Test
	public void testAnExceptionMessageAndCauseAreMasked() {
		MaskingThrowableConverter converter = new MaskingThrowableConverter();
		converter.start();

		String trace = converter.convert(event("failed", new IllegalStateException(
				"parse error near " + GITHUB_PAT, new RuntimeException("cause " + GITHUB_PAT))));

		MatcherAssert.assertThat(trace, Matchers.not(Matchers.containsString(GITHUB_PAT)));
		MatcherAssert.assertThat(trace, Matchers.containsString("IllegalStateException"));
		MatcherAssert.assertThat(trace, Matchers.containsString("ghp_****"));
	}
}
