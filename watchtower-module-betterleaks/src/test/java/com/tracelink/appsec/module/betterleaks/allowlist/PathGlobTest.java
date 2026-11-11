package com.tracelink.appsec.module.betterleaks.allowlist;

import java.util.regex.Pattern;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

public class PathGlobTest {

	@ParameterizedTest
	@CsvSource({
			"src/test/fixtures/**, src/test/fixtures/keys/fake.pem, true",
			"src/test/fixtures/**, src/main/App.java, false",
			"**/testdata/*.json, a/b/testdata/token.json, true",
			"**/testdata/*.json, testdata/token.json, true",
			"**/testdata/*.json, testdata/nested/token.json, false",
			"docs/example?.md, docs/example1.md, true",
			"docs/example?.md, docs/example12.md, false",
			// No slash: matches the file name at any depth, like .gitignore.
			"*.lock, yarn.lock, true",
			"*.lock, frontend/yarn.lock, true",
			"*.lock, frontend/yarn.locks, false",
			// Dots are literal.
			"app.properties, appXproperties, false",
			"config/app.properties, config/app.properties, true",
			"config/app.properties, other/config/app.properties, false"
	})
	public void testRegexMatchesLikeTheGlob(String glob, String path, boolean expected) {
		String regex = PathGlob.of(glob).toRegex();

		Assertions.assertEquals(expected, Pattern.matches(regex, path),
				glob + " -> " + regex + " against " + path);
	}

	@ParameterizedTest
	@ValueSource(strings = {"**", "*", "**/*", "/", "*/**", "?", "**/**"})
	public void testRejectsAGlobThatWouldAllowlistEverything(String glob) {
		Assertions.assertThrows(IllegalArgumentException.class, () -> PathGlob.of(glob));
	}

	@ParameterizedTest
	@ValueSource(strings = {"a'''b", "a\nb", "a\"b", "a b", "a[b]", "a{b,c}", "/abs/path",
			"a/../b", "a\\b", "(a)", "a|b", "a+b", "$HOME", ""})
	public void testRejectsCharactersOutsideTheSafeSet(String glob) {
		Assertions.assertThrows(IllegalArgumentException.class, () -> PathGlob.of(glob));
	}

	@Test
	public void testRejectsNullAndOverlongGlobs() {
		Assertions.assertThrows(IllegalArgumentException.class, () -> PathGlob.of(null));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> PathGlob.of("a/".repeat(200)));
	}

	@Test
	public void testTrimsSurroundingWhitespace() {
		Assertions.assertEquals("src/**", PathGlob.of("  src/**  ").glob());
	}
}
