package com.tracelink.appsec.watchtower.maven.plugin;

import com.tracelink.appsec.watchtower.cli.executor.UploadScanExecutor;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;
import org.springframework.test.util.ReflectionTestUtils;

public class UploadScanMojoTest {

	@RegisterExtension
	public LogWatchExtension loggerRule =
			LogWatchExtension.forClass(UploadScanExecutor.class);

	private Path resourcesDir;
	private final String watchtowerUrl = "https://example.com";
	private final String apiKeyId = UUID.randomUUID().toString();
	private final String apiSecret = UUID.randomUUID().toString();

	@BeforeEach
	public void init() throws Exception {
		resourcesDir = Paths.get(getClass().getClassLoader().getResource("maven-project").toURI())
				.getParent();
	}

	@Test
	public void testExecuteOnlyRequiredFields() throws Exception {
		UploadScanMojo mojo = new UploadScanMojo();
		MavenProject mavenProject = BDDMockito.mock(MavenProject.class);
		BDDMockito.when(mavenProject.getBasedir())
				.thenReturn(resourcesDir.resolve("maven-project").toFile());
		ReflectionTestUtils.setField(mojo, "project", mavenProject);
		ReflectionTestUtils.setField(mojo, "watchtowerUrl", watchtowerUrl);
		ReflectionTestUtils.setField(mojo, "watchtowerApiKeyId", apiKeyId);
		ReflectionTestUtils.setField(mojo, "watchtowerApiSecret", apiSecret);

		mojo.execute();
		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("Zipping target for upload to Watchtower",
						"Starting Watchtower upload scan"));
	}

	@Test
	public void testExecuteAllFields() throws Exception {
		UploadScanMojo mojo = new UploadScanMojo();
		MavenProject mavenProject = BDDMockito.mock(MavenProject.class);
		BDDMockito.when(mavenProject.getBasedir())
				.thenReturn(resourcesDir.resolve("maven-project").toFile());
		ReflectionTestUtils.setField(mojo, "project", mavenProject);
		ReflectionTestUtils.setField(mojo, "watchtowerUrl", watchtowerUrl);
		ReflectionTestUtils.setField(mojo, "watchtowerApiKeyId", apiKeyId);
		ReflectionTestUtils.setField(mojo, "watchtowerApiSecret", apiSecret);
		ReflectionTestUtils
				.setField(mojo, "target",
						resourcesDir.resolve("maven-project/target/File.java").toString());
		ReflectionTestUtils.setField(mojo, "output", resourcesDir.toString());
		ReflectionTestUtils.setField(mojo, "fileName", "foo.zip");
		ReflectionTestUtils.setField(mojo, "ruleset", "Primary");

		mojo.execute();
		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("Zipping target for upload to Watchtower",
						"Starting Watchtower upload scan"));
	}

	@Test
	public void testExecuteBadTarget() throws Exception {
		UploadScanMojo mojo = new UploadScanMojo();
		MavenProject mavenProject = BDDMockito.mock(MavenProject.class);
		BDDMockito.when(mavenProject.getBasedir())
				.thenReturn(resourcesDir.resolve("invalid").toFile());
		ReflectionTestUtils.setField(mojo, "project", mavenProject);
		ReflectionTestUtils.setField(mojo, "watchtowerUrl", watchtowerUrl);
		ReflectionTestUtils.setField(mojo, "watchtowerApiKeyId", apiKeyId);
		ReflectionTestUtils.setField(mojo, "watchtowerApiSecret", apiSecret);

		try {
			mojo.execute();
		} catch (MojoExecutionException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.is("An exception occurred while performing Watchtower upload scan"));
		}
		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("Zipping target for upload to Watchtower"));
	}
}
