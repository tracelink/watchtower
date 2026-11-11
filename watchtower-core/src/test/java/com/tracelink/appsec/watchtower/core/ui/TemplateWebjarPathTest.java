package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;

/**
 * Guards against the "pom bump without template edit" failure mode
 * (IMPROVEMENT_PLAN.md, Phase 11 REMAINING WORK, Safety net I): a webjar
 * dependency's version changes in a {@code pom.xml}, but a template still
 * hardcodes the old version in its {@code /webjars/...} URL, producing a
 * silent 404 in the browser instead of a build failure.
 *
 * <p>Every {@code /webjars/<artifact>/<version>/<path>} URL is checked
 * against {@code META-INF/resources/webjars/<artifact>/<version>/<path>} on
 * the test classpath - the exact lookup Spring Boot's webjar resource
 * handler performs at runtime.
 */
class TemplateWebjarPathTest {

	private static final Pattern WEBJAR_URL_PATTERN = Pattern.compile("/webjars/([^\"'\\s)]+)");

	@Test
	void everyWebjarUrlInEveryTemplateResolvesOnTheClasspath() throws IOException {
		Set<String> checkedUrls = new LinkedHashSet<>();
		Set<String> missingUrls = new LinkedHashSet<>();
		ClassLoader classLoader = getClass().getClassLoader();

		for (Path template : TemplateModuleScanner.findAllTemplateFiles()) {
			String content = Files.readString(template);
			Matcher matcher = WEBJAR_URL_PATTERN.matcher(content);
			while (matcher.find()) {
				String resourcePath = matcher.group(1);
				checkedUrls.add(resourcePath);
				String classpathResource = "META-INF/resources/webjars/" + resourcePath;
				if (classLoader.getResource(classpathResource) == null) {
					missingUrls.add(resourcePath + " (referenced in " + template + ")");
				}
			}
		}

		assertTrue(!checkedUrls.isEmpty(),
				"Expected to find /webjars/ URLs across the templates, but found "
						+ checkedUrls.size()
						+ " - the template scan or the URL regex may be broken");
		assertTrue(missingUrls.isEmpty(),
				"The following /webjars/ URLs do not resolve on the classpath. This usually "
						+ "means a webjar version was bumped in a pom.xml without updating the "
						+ "matching template path:\n" + String.join("\n", missingUrls));
	}
}
