package com.tracelink.appsec.watchtower.core.logging;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.CyclicBufferAppender;

/**
 * The masking rules in logback-spring.xml reach what an admin sees in the in-app log viewer,
 * for both the message and a stack trace.
 * <p>
 * Reads the logging context as it is now rather than the cached context's {@code LogsService}
 * bean: every Spring context in the suite re-initializes logback, which can leave that bean
 * holding a detached buffer.
 */
@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
public class LogMaskingIntegrationTest {

	/** Synthetic, split so that no secrets scanner flags this source file. */
	private static final String GITHUB_PAT = "ghp_" + "Xa9Bc3De5Fg7Hi1Jk3Lm5No7Pq9Rs1Tu3Vw5";

	@Test
	@SuppressWarnings("unchecked")
	public void testTheLogViewerNeverShowsAKnownTokenFormat() {
		LoggerContext context = (LoggerContext) LoggerFactory.getILoggerFactory();
		Logger appLogger = context.getLogger("com.tracelink.appsec");
		CyclicBufferAppender<ILoggingEvent> buffer = (CyclicBufferAppender<ILoggingEvent>) appLogger
				.getAppender(LogsService.APPENDER_NAME);
		Assertions.assertNotNull(buffer, "logback-spring.xml did not configure the log viewer");
		LogsService logsService = new LogsService(buffer, appLogger);
		logsService.prepareEncoder();

		context.getLogger(LogMaskingIntegrationTest.class).warn("Bitbucket said: {}", GITHUB_PAT,
				new IllegalStateException("unparseable near " + GITHUB_PAT));

		String logs = String.join("\n", logsService.getLogs());
		MatcherAssert.assertThat(logs, Matchers.containsString("Bitbucket said: ghp_****"));
		MatcherAssert.assertThat(logs, Matchers.containsString("IllegalStateException"));
		MatcherAssert.assertThat(logs, Matchers.not(Matchers.containsString(GITHUB_PAT)));
	}
}
