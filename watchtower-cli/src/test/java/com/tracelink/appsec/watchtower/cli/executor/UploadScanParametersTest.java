package com.tracelink.appsec.watchtower.cli.executor;

import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class UploadScanParametersTest {

	@RegisterExtension
	public LogWatchExtension loggerRule =
			LogWatchExtension.forClass(UploadScanParameters.class);

	@Test
	public void testParseArgs() {
		UploadScanParameters parameters = new UploadScanParameters();
		parameters.parseArgs(
				new String[]{"-u", "https://example.com", "-k", "key", "-s", "secret", "-t", "foo",
						"-n", "file"});
		MatcherAssert.assertThat(parameters.getServerUrl(), Matchers.is("https://example.com"));
		MatcherAssert.assertThat(parameters.getApiKeyId(), Matchers.is("key"));
		MatcherAssert.assertThat(parameters.getApiSecret(), Matchers.is("secret"));
		MatcherAssert.assertThat(parameters.getTarget(), Matchers.is("foo"));
		MatcherAssert.assertThat(parameters.getOutput(), Matchers.nullValue());
		MatcherAssert.assertThat(parameters.getFileName(), Matchers.is("file"));
		MatcherAssert.assertThat(parameters.getRuleset(), Matchers.nullValue());
	}

	@Test
	public void testParseArgsMissingRequired() {
		UploadScanParameters parameters = new UploadScanParameters();
		parameters.parseArgs(
				new String[]{"-k", "key", "-s", "secret", "-t", "foo", "-n", "file"});
		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.contains(
						"Exception occurred while parsing arguments. Missing required option: u"));
	}

}
