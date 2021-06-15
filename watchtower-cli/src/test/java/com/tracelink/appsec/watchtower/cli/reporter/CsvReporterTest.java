package com.tracelink.appsec.watchtower.cli.reporter;

import com.tracelink.appsec.watchtower.cli.scan.ScanStatus;
import com.tracelink.appsec.watchtower.cli.scan.UploadScanResult;
import com.tracelink.appsec.watchtower.cli.scan.UploadScanResultViolation;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.io.FileUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class CsvReporterTest {

	@RegisterExtension
	public LogWatchExtension loggerRule =
			LogWatchExtension.forClass(CsvReporter.class);

	@Test
	public void testReportNullResult() {
		CsvReporter reporter = new CsvReporter("foo");
		reporter.reportSummary(null);
		reporter.report(null);

		MatcherAssert.assertThat(loggerRule.getMessages(), Matchers.empty());
	}

	@Test
	public void testReportViolations() throws Exception {
		UploadScanResultViolation violation = new UploadScanResultViolation();
		violation.setExternalUrl("https://example.com");
		violation.setFileName("file.js");
		violation.setViolationName("Console.log()");
		violation.setMessage("Don't use it");
		violation.setSeverity("Low");
		violation.setSeverityValue(4);
		violation.setLineNumber(1);

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
		result.setViolations(Collections.singletonList(violation));

		Path output = Paths
				.get(getClass().getClassLoader().getResource("output/existing.csv").toURI())
				.toAbsolutePath();
		new CsvReporter(output.toString()).report(result);

		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("No errors to report to CSV"));
		MatcherAssert.assertThat(output.resolve("existing-errors.csv").toFile().exists(),
				Matchers.is(false));

		try (CSVParser parser = new CSVParser(
				Files.newBufferedReader(output),
				CSVFormat.DEFAULT.withFirstRecordAsHeader())) {
			Map<String, Integer> headers = parser.getHeaderMap();
			MatcherAssert.assertThat(headers.keySet(),
					Matchers.hasItems("File Name", "Violation", "Severity", "Severity Value",
							"Line Num", "Message", "External URL"));
			List<CSVRecord> records = parser.getRecords();
			MatcherAssert.assertThat(records.size(), Matchers.is(1));
			MatcherAssert.assertThat(records.get(0),
					Matchers.contains(violation.getFileName(), violation.getViolationName(),
							violation.getSeverity(), String.valueOf(violation.getSeverityValue()),
							String.valueOf(violation.getLineNumber()), violation.getMessage(),
							violation.getExternalUrl()));

		}
	}

	@Test
	public void testReportErrors() throws Exception {
		Path output = Paths.get(getClass().getClassLoader().getResource("output").toURI());
		UploadScanResult result = new UploadScanResult();
		result.setStatus(ScanStatus.FAILED.getDisplayName());
		String ticket = UUID.randomUUID().toString();
		result.setTicket(ticket);
		result.setRuleset("default");
		result.setName("scan.zip");
		result.setSubmittedBy("jdoe");
		LocalDateTime date = LocalDateTime.now();
		result.setSubmitDate(date.minusSeconds(20));
		result.setEndDate(date);
		String error = "An error occurred";
		result.setErrorMessage(error);
		new CsvReporter(output.toString()).report(result);

		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("No violations to report to CSV"));
		MatcherAssert.assertThat(output.resolve("scan-report.csv").toFile().exists(),
				Matchers.is(false));

		try (CSVParser parser = new CSVParser(
				Files.newBufferedReader(output.resolve("scan-errors.csv")),
				CSVFormat.DEFAULT.withFirstRecordAsHeader())) {
			Map<String, Integer> headers = parser.getHeaderMap();
			MatcherAssert.assertThat(headers.keySet(),
					Matchers.hasItems("Error Message"));
			List<CSVRecord> records = parser.getRecords();
			MatcherAssert.assertThat(records.size(), Matchers.is(1));
			MatcherAssert.assertThat(records.get(0), Matchers.contains(error));
		}

		FileUtils.deleteQuietly(output.resolve("scan-errors.csv").toFile());
	}
}
