package com.tracelink.appsec.watchtower.cli;

import com.tracelink.appsec.watchtower.cli.executor.UploadScanExecutor;
import com.tracelink.appsec.watchtower.cli.executor.UploadScanParameters;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class WatchtowerCliTest {

	@RegisterExtension
	public LogWatchExtension cliLoggerRule =
			LogWatchExtension.forClass(WatchtowerCli.class);

	@RegisterExtension
	public LogWatchExtension paramsLoggerRule =
			LogWatchExtension.forClass(UploadScanParameters.class);

	@RegisterExtension
	public LogWatchExtension executorLoggerRule =
			LogWatchExtension.forClass(UploadScanExecutor.class);

	@Test
	public void testWatchtowerCliBadArgs() {
		WatchtowerCli.main(new String[]{"-k", "key", "-s", "secret", "-t", "foo", "-n", "file"});
		MatcherAssert.assertThat(paramsLoggerRule.getMessages(),
				Matchers.contains(
						"Exception occurred while parsing arguments. Missing required option: u"));
	}

	@Test
	public void testWatchtowerCli() {
		WatchtowerCli
				.main(new String[]{"-u", "https://example.com", "-k", "key", "-s", "secret", "-t",
						"foo", "-n", "file"});
		MatcherAssert.assertThat(executorLoggerRule.getMessages(),
				Matchers.hasItem("Zipping target for upload to Watchtower"));
	}

	@Test
	public void testWatchtowerCliException() {
		WatchtowerCli
				.main(new String[]{"-u", "https://example.com", "-k", "key", "-s", "secret", "-t",
						"foo", "-n", "file"});
		MatcherAssert.assertThat(cliLoggerRule.getMessages(),
				Matchers.contains("An exception occurred while performing Watchtower upload scan"));
	}
}
