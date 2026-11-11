package com.tracelink.appsec.watchtower.core.alerting;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class AlertWordingTest {

	@Test
	void repeatWindowsReadInDaysWhenWhole() {
		Assertions.assertEquals("30 days", AlertWording.window(720));
		Assertions.assertEquals("1 day", AlertWording.window(24));
		Assertions.assertEquals("36 hours", AlertWording.window(36));
		Assertions.assertEquals("1 hour", AlertWording.window(1));
	}

	@Test
	void deliveryTimeIsShort() {
		Assertions.assertEquals("4 s", AlertWording.lag(1_000L, 5_000L));
		Assertions.assertEquals("3 min", AlertWording.lag(0L, 180_000L));
		Assertions.assertEquals("2 h", AlertWording.lag(0L, 7_200_000L));
		Assertions.assertEquals("", AlertWording.lag(0L, null), "not delivered yet");
	}

	@Test
	void alertKeysReadAsNamesWithAnIcon() {
		Assertions.assertEquals("Secret detected", AlertWording.name("SECRET_DETECTED"));
		Assertions.assertEquals("PR bypass requested", AlertWording.name("PR_BYPASS_REQUESTED"), "PR is an acronym, not a word");
		Assertions.assertEquals("Sent", AlertWording.name("SENT"));
		Assertions.assertEquals("key", AlertWording.icon("SECRET_DETECTED"));
		Assertions.assertEquals("error_outline", AlertWording.icon("Scanner failure"));
		Assertions.assertEquals("notifications", AlertWording.icon(null));
	}
}
