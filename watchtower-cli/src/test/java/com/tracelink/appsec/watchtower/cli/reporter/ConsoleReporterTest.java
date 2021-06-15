package com.tracelink.appsec.watchtower.cli.reporter;

import com.tracelink.appsec.watchtower.cli.scan.ScanStatus;
import com.tracelink.appsec.watchtower.cli.scan.UploadScanResult;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.UUID;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class ConsoleReporterTest {

	@RegisterExtension
	public LogWatchExtension loggerRule =
			LogWatchExtension.forClass(ConsoleReporter.class);

	@Test
	public void testReportNullResult() {
		ConsoleReporter reporter = new ConsoleReporter();
		reporter.reportSummary(null);
		reporter.report(null);
		MatcherAssert.assertThat(loggerRule.getMessages(), Matchers.empty());
	}

	@Test
	public void testReportNoViolations() {
		UploadScanResult result = new UploadScanResult();
		result.setStatus(ScanStatus.DONE.getDisplayName());
		String ticket = UUID.randomUUID().toString();
		result.setTicket(ticket);
		result.setRuleset("default");
		result.setName("scan.zip");
		result.setSubmittedBy("jdoe");
		LocalDateTime date = LocalDateTime.now();
		result.setSubmitDate(date.minusMinutes(2).minusSeconds(20));
		result.setEndDate(date);
		result.setViolations(Collections.emptyList());
		String error = "An error occurred";
		result.setErrorMessage(error);
		new ConsoleReporter().report(result);

		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("No violations to report to console", "Errors", error));
	}
}
