package com.tracelink.appsec.watchtower.cli.executor;

import static com.github.tomakehurst.wiremock.client.WireMock.aMultipart;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.tracelink.appsec.watchtower.cli.WireMockExtension;
import com.tracelink.appsec.watchtower.cli.reporter.ConsoleReporter;
import com.tracelink.appsec.watchtower.cli.reporter.CsvReporter;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.upload.result.UploadScanResult;
import com.tracelink.appsec.watchtower.core.scan.upload.result.UploadScanResultViolation;
import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.UUID;
import org.apache.commons.io.FileUtils;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class UploadScanExecutorTest {

	@RegisterExtension
	public WireMockExtension wireMockExtension =
			new WireMockExtension(WireMockConfiguration.wireMockConfig().dynamicPort());

	@RegisterExtension
	public LogWatchExtension loggerRule =
			LogWatchExtension.forClass(UploadScanExecutor.class);

	@RegisterExtension
	public LogWatchExtension csvLoggerRule =
			LogWatchExtension.forClass(CsvReporter.class);

	@RegisterExtension
	public LogWatchExtension consoleLoggerRule =
			LogWatchExtension.forClass(ConsoleReporter.class);

	private String apiBase;
	private Path resourcesDir;
	private static final String ENDPOINT = "/rest/uploadscan";
	private static final String API_KEY = "apiKey";
	private static final String API_SECRET = "apiSecret";
	private static final Gson GSON = new GsonBuilder().registerTypeAdapter(LocalDateTime.class,
			new LocalDateTimeTypeAdapter()).create();

	@BeforeEach
	public void init() throws Exception {
		wireMockExtension.resetMappings();
		apiBase = wireMockExtension.baseUrl();
		resourcesDir = Paths.get(getClass().getClassLoader().getResource("scan").toURI())
				.getParent();
	}

	@Test
	public void testExecuteUploadScanInvalidTarget() throws Exception {
		String target = resourcesDir.resolve("invalid").toString();
		String output = resourcesDir.toString();
		UploadScanParameters params = configureParameters(apiBase, target, output, "myScan.zip",
				"primary");
		UploadScanExecutor executor = new UploadScanExecutor(params);
		try {
			executor.executeUploadScan();
			MatcherAssert.assertThat("Should have thrown exception", false);
		} catch (IllegalArgumentException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.is("Target directory or file must exist"));
		}

		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("Zipping target for upload to Watchtower"));
	}

	@Test
	public void testExecuteUploadScan400PostResponse() throws Exception {
		String target = resourcesDir.resolve("scan").toString();
		String output = resourcesDir.toString();
		UploadScanParameters params = configureParameters(apiBase, target, output, "myScan.zip",
				"primary");
		UploadScanExecutor executor = new UploadScanExecutor(params);

		WireMock.stubFor(WireMock.post(ENDPOINT).withBasicAuth(API_KEY, API_SECRET)
				.withMultipartRequestBody(aMultipart()
						.withHeader("Content-Disposition",
								containing("form-data; name=\"name\"\n\n" + params.getFileName()))
						.withHeader("Content-Disposition",
								containing("form-data; name=\"ruleset\"\n\n" + params.getRuleset()))
						.withName("uploadFile"))
				.willReturn(WireMock.aResponse().withStatus(400)));
		executor.executeUploadScan();

		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItem("Received status code 400 while trying to start upload scan"));
	}

	@Test
	public void testExecuteUploadScanNullStatus() throws Exception {
		String target = resourcesDir.resolve("scan").toString();
		String output = resourcesDir.toString();
		UploadScanParameters params = configureParameters(apiBase, target, output, "myScan.zip",
				"primary");

		UploadScanResult result = new UploadScanResult();
		result.setStatus("foo");
		WireMock.stubFor(WireMock.post(ENDPOINT).withBasicAuth(API_KEY, API_SECRET)
				.withMultipartRequestBody(aMultipart()
						.withHeader("Content-Disposition",
								containing("form-data; name=\"name\"\n\n" + params.getFileName()))
						.withHeader("Content-Disposition",
								containing("form-data; name=\"ruleset\"\n\n" + params.getRuleset()))
						.withName("uploadFile"))
				.willReturn(WireMock.okJson(GSON.toJson(result))));

		UploadScanExecutor executor = new UploadScanExecutor(params);
		executor.executeUploadScan();

		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("Zipping target for upload to Watchtower",
						"Starting Watchtower upload scan",
						"Unknown scan status in Watchtower response: foo"));
	}

	@Test
	public void testExecuteUploadScanBlankTicket() throws Exception {
		String target = resourcesDir.resolve("scan").toString();
		String output = resourcesDir.toString();
		UploadScanParameters params = configureParameters(apiBase, target, output, "myScan.zip",
				"primary");

		UploadScanResult result = new UploadScanResult();
		result.setStatus(ScanStatus.NOT_STARTED.getDisplayName());
		result.setTicket(null);

		WireMock.stubFor(WireMock.post(ENDPOINT).withBasicAuth(API_KEY, API_SECRET)
				.withMultipartRequestBody(aMultipart()
						.withHeader("Content-Disposition",
								containing("form-data; name=\"name\"\n\n" + params.getFileName()))
						.withHeader("Content-Disposition",
								containing("form-data; name=\"ruleset\"\n\n" + params.getRuleset()))
						.withName("uploadFile"))
				.willReturn(WireMock.okJson(GSON.toJson(result))));

		UploadScanExecutor executor = new UploadScanExecutor(params);
		executor.executeUploadScan();

		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("Zipping target for upload to Watchtower",
						"Starting Watchtower upload scan",
						"Cannot get scan results for a blank scan ticket"));
	}

	@Test
	public void testExecuteUploadScan400GetResponse() throws Exception {
		String target = resourcesDir.resolve("scan").toString();
		String output = resourcesDir.toString();
		UploadScanParameters params = configureParameters(apiBase, target, output, "myScan.zip",
				"primary");

		UploadScanResult result = new UploadScanResult();
		result.setStatus(ScanStatus.IN_PROGRESS.getDisplayName());
		String ticket = UUID.randomUUID().toString();
		result.setTicket(ticket);

		WireMock.stubFor(WireMock.post(ENDPOINT).withBasicAuth(API_KEY, API_SECRET)
				.withMultipartRequestBody(aMultipart()
						.withHeader("Content-Disposition",
								containing("form-data; name=\"name\"\n\n" + params.getFileName()))
						.withHeader("Content-Disposition",
								containing("form-data; name=\"ruleset\"\n\n" + params.getRuleset()))
						.withName("uploadFile"))
				.willReturn(WireMock.okJson(GSON.toJson(result))));

		WireMock.stubFor(WireMock.get(ENDPOINT + "/" + ticket).withBasicAuth(API_KEY, API_SECRET)
				.willReturn(WireMock.aResponse().withStatus(400)));

		UploadScanExecutor executor = new UploadScanExecutor(params);
		executor.executeUploadScan();

		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("Zipping target for upload to Watchtower",
						"Starting Watchtower upload scan", "Waiting before sending request",
						"Received status code 400 while trying to get scan results for ticket "
								+ ticket));
	}

	@Test
	public void testExecuteUploadScanRetrySuccessNoRulesetOrName() throws Exception {
		String target = resourcesDir.resolve("scan").toString();
		String output = resourcesDir.toString();
		UploadScanParameters params = configureParameters(apiBase, target, output, null,
				null);

		UploadScanResult result1 = new UploadScanResult();
		result1.setStatus(ScanStatus.IN_PROGRESS.getDisplayName());
		String ticket = UUID.randomUUID().toString();
		result1.setTicket(ticket);

		WireMock.stubFor(WireMock.post(ENDPOINT).withBasicAuth(API_KEY, API_SECRET)
				.withMultipartRequestBody(aMultipart()
						.withHeader("Content-Disposition",
								containing("form-data; name=\"name\"\n\n" + "scan.zip"))
						.withName("uploadFile"))
				.willReturn(WireMock.okJson(GSON.toJson(result1))));

		UploadScanResult result2 = new UploadScanResult();
		result2.setStatus(ScanStatus.DONE.getDisplayName());
		result2.setTicket(ticket);
		result2.setRuleset("default");
		result2.setName("scan.zip");
		result2.setSubmittedBy("jdoe");
		LocalDateTime date = LocalDateTime.now();
		result2.setSubmitDate(date.minusMinutes(2).minusSeconds(20));
		result2.setEndDate(date);
		result2.setViolations(Collections.emptyList());

		WireMock.stubFor(WireMock.get(ENDPOINT + "/" + ticket).withBasicAuth(API_KEY, API_SECRET)
				.willReturn(WireMock.okJson(GSON.toJson(result2))));

		UploadScanExecutor executor = new UploadScanExecutor(params);
		executor.executeUploadScan();

		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("Zipping target for upload to Watchtower",
						"Starting Watchtower upload scan", "Waiting before sending request",
						"Reporting scan results"));
		MatcherAssert.assertThat(csvLoggerRule.getMessages(),
				Matchers.hasItems("Scan Duration:  2 minutes, 20 seconds", "Num Violations: 0"));

		MatcherAssert.assertThat(resourcesDir.resolve("scan-report.csv").toFile().exists(),
				Matchers.is(false));
		MatcherAssert.assertThat(resourcesDir.resolve("scan-errors.csv").toFile().exists(),
				Matchers.is(false));
		FileUtils.deleteQuietly(resourcesDir.resolve("scan-report.csv").toFile());
	}

	@Test
	public void testExecuteUploadScanConsole() throws Exception {
		String target = resourcesDir.resolve("scan").toString();
		UploadScanParameters params = configureParameters(apiBase, target, null, null,
				null);

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

		WireMock.stubFor(WireMock.post(ENDPOINT).withBasicAuth(API_KEY, API_SECRET)
				.withMultipartRequestBody(aMultipart()
						.withHeader("Content-Disposition",
								containing("form-data; name=\"name\"\n\n" + "scan.zip"))
						.withName("uploadFile"))
				.willReturn(WireMock.okJson(GSON.toJson(result))));

		UploadScanExecutor executor = new UploadScanExecutor(params);
		executor.executeUploadScan();

		MatcherAssert.assertThat(loggerRule.getMessages(),
				Matchers.hasItems("Zipping target for upload to Watchtower",
						"Starting Watchtower upload scan", "Reporting scan results"));
		MatcherAssert.assertThat(consoleLoggerRule.getMessages(),
				Matchers.hasItems("Scan Duration:  2 minutes, 20 seconds", "Num Violations: 1",
						"Violation:       Console.log()", "Message:         Don't use it"));
	}

	private static UploadScanParameters configureParameters(String serverUrl, String target,
			String output, String fileName, String ruleset) {
		UploadScanParameters params = new UploadScanParameters();
		params.setServerUrl(serverUrl);
		params.setApiKeyId(API_KEY);
		params.setApiSecret(API_SECRET);
		params.setTarget(target);
		params.setOutput(output);
		params.setFileName(fileName);
		params.setRuleset(ruleset);
		return params;
	}
}
