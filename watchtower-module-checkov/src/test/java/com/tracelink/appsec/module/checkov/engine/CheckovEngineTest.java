package com.tracelink.appsec.module.checkov.engine;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

import org.apache.commons.io.FileUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.checkov.model.CheckovProvidedRuleDto;

public class CheckovEngineTest {

	@Test
	public void testCheckovEngineSetup() throws Exception {
		Path targetDirectory = null;
		try {
			targetDirectory = Files.createTempDirectory(null);
			try (InputStream is =
					this.getClass()
							.getResourceAsStream("/terraformtest/terraform_iam.tf")) {
				Files.copy(is, targetDirectory.resolve("terraform_test.tf"));
			}
			CheckovEngine engine = new CheckovEngine();
			MatcherAssert.assertThat(engine.getCoreRules(),
					Matchers.hasSize(Matchers.greaterThan(0)));
			CheckovProvidedRuleDto rule = new CheckovProvidedRuleDto();
			rule.setName("TEST");
			// rather than test that checkov finds anything (I'm not testing checkov), test that the
			// directory scan doesn't throw issues
			engine.runCheckovDirectoryScan(targetDirectory, Arrays.asList(rule));
		} finally {
			if (targetDirectory != null) {
				FileUtils.deleteQuietly(targetDirectory.toFile());
			}
		}
	}
}
