package com.tracelink.appsec.module.betterleaks.verify;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SecretWindowTest {

	private static String lines(int count) {
		StringBuilder text = new StringBuilder();
		for (int i = 1; i <= count; i++) {
			text.append("line ").append(i).append('\n');
		}
		return text.toString();
	}

	@Test
	public void testKeepsFiveLinesEitherSideAndMapsTheFlaggedLine() {
		SecretWindow window = SecretWindow.around(lines(30), 12);

		Assertions.assertEquals(lines(17).substring(lines(6).length()), window.text());
		Assertions.assertEquals(6, window.flaggedLine());
	}

	@Test
	public void testIsClippedAtTheStartAndEndOfTheFile() {
		SecretWindow start = SecretWindow.around(lines(4), 2);
		Assertions.assertEquals(lines(4), start.text());
		Assertions.assertEquals(2, start.flaggedLine());

		SecretWindow end = SecretWindow.around(lines(10), 10);
		Assertions.assertEquals(lines(10).substring(lines(4).length()), end.text());
		Assertions.assertEquals(6, end.flaggedLine());
	}

	@Test
	public void testHandlesWindowsLineEndings() {
		SecretWindow window = SecretWindow.around("a\r\nb\r\nc\r\n", 2);

		Assertions.assertEquals("a\nb\nc\n", window.text());
		Assertions.assertEquals(2, window.flaggedLine());
	}

	@Test
	public void testALineOutsideTheFileHasNoWindow() {
		Assertions.assertNull(SecretWindow.around(lines(3), 4));
		Assertions.assertNull(SecretWindow.around(lines(3), 0));
		Assertions.assertNull(SecretWindow.around("", 1));
	}
}
