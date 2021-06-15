package com.tracelink.appsec.watchtower.cli.executor;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.tracelink.appsec.watchtower.cli.reporter.AbstractReporter;
import com.tracelink.appsec.watchtower.cli.reporter.ConsoleReporter;
import com.tracelink.appsec.watchtower.cli.reporter.CsvReporter;
import com.tracelink.appsec.watchtower.cli.scan.ScanStatus;
import com.tracelink.appsec.watchtower.cli.scan.UploadScanResult;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import kong.unirest.HttpResponse;
import kong.unirest.Unirest;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles execution of a Watchtower upload scan given a set of parameters for configuration. Zips
 * target code, uploads to Watchtower for scanning, and reports results to the console or CSV.
 *
 * @author mcool
 */
public class UploadScanExecutor {

	private static final Logger LOG = LoggerFactory.getLogger(UploadScanExecutor.class);
	private static final String UPLOAD_SCAN_ENDPOINT = "rest/uploadscan";
	private static final int NUM_RETRIES = 10;
	private static final int SLEEP_SECONDS = 6;
	private static final Gson GSON = new GsonBuilder().registerTypeAdapter(LocalDateTime.class,
			new LocalDateTimeTypeAdapter()).create();

	private final UploadScanParameters params;

	public UploadScanExecutor(UploadScanParameters params) {
		this.params = params;
	}

	/**
	 * Executes the Watchtower upload scan using the {@link UploadScanParameters} for this class.
	 *
	 * @throws IOException          if there is an IO problem with the target or output files
	 * @throws InterruptedException if there is a problem sleeping while polling for scan results
	 */
	public void executeUploadScan() throws IOException, InterruptedException {
		Path zipPath = zipTarget(params.getTarget());
		UploadScanResult result = initiateUploadScan(zipPath);
		pollForScanResults(result);
		FileUtils.deleteQuietly(zipPath.toFile());
	}

	/**
	 * Zips the given target file or directory and returns the path to the zipped file.
	 *
	 * @param target the file or directory to zip
	 * @return path to the zipped file
	 * @throws IllegalArgumentException if the target directory or file does not exist
	 * @throws IOException              if there is a problem creating the zip file
	 */
	private Path zipTarget(String target) throws IllegalArgumentException, IOException {
		LOG.info("Zipping target for upload to Watchtower");
		// Make sure target file/folder exists
		File targetFile = new File(target);
		if (!targetFile.exists()) {
			throw new IllegalArgumentException("Target directory or file must exist");
		}
		// Create zip file
		Path zipPath = Files.createTempFile(null, ".zip");
		ZipParameters zipParams = new ZipParameters();
		zipParams.setReadHiddenFiles(false);
		zipParams.setReadHiddenFolders(false);
		ZipFile zipFile = new ZipFile(zipPath.toFile());
		FileUtils.deleteQuietly(zipPath.toFile()); // Needed for the Zip4j library to work
		// Add target file/folder to zip file
		if (targetFile.isFile()) {
			zipFile.addFile(targetFile, zipParams);
		} else {
			zipFile.addFolder(targetFile, zipParams);
		}
		return zipPath;
	}

	/**
	 * Initiates the Watchtower upload scan and uploads the zip file at the given path.
	 *
	 * @param zipPath the path of the zip file to scan with Watchtower
	 * @return the initial response from starting the Watchtower scan, or null if the response is
	 * not successful
	 */
	private UploadScanResult initiateUploadScan(Path zipPath) {
		LOG.info("Starting Watchtower upload scan");
		String serverUrl = params.getServerUrl();
		if (!serverUrl.endsWith("/")) {
			serverUrl += "/";
		}
		String url = serverUrl + UPLOAD_SCAN_ENDPOINT;
		Map<String, Object> fields = new HashMap<>();
		fields.put("name",
				StringUtils.isBlank(params.getFileName()) ? new File(params.getTarget()).getName()
						+ ".zip" : params.getFileName());
		if (!StringUtils.isBlank(params.getRuleset())) {
			fields.put("ruleset", params.getRuleset());
		}
		fields.put("uploadFile", zipPath.toFile());
		HttpResponse<String> response = Unirest.post(url).fields(fields)
				.basicAuth(params.getApiKeyId(), params.getApiSecret()).asString();
		if (response.isSuccess()) {
			UploadScanResult result = GSON.fromJson(response.getBody(), UploadScanResult.class);
			if (!StringUtils.isBlank(result.getTicket())) {
				LOG.info("Received scan ticket '" + result.getTicket() + "' from Watchtower");
			}
			return result;
		} else {
			LOG.error("Received status code " + response.getStatus()
					+ " while trying to start upload scan");
			LOG.error(response.getBody());
			return null;
		}
	}

	/**
	 * Polls for scan results from Watchtower until the scan finishes either successfully or with a
	 * failure.
	 *
	 * @param scanResult the initial result from Watchtower after starting the scan
	 * @throws InterruptedException if there is a problem sleeping between requests
	 */
	private void pollForScanResults(UploadScanResult scanResult)
			throws InterruptedException {
		int retries = NUM_RETRIES;
		while (retries >= 0) {
			if (scanResult == null) {
				return;
			}
			ScanStatus scanStatus = ScanStatus.toStatus(scanResult.getStatus());
			if (scanStatus == null) {
				LOG.warn("Unknown scan status in Watchtower response: " + scanResult.getStatus());
				return;
			} else {
				switch (scanStatus) {
					case DONE:
					case FAILED:
						LOG.info("Reporting scan results");
						reportScanResults(params.getOutput(), scanResult);
						return;
					case NOT_STARTED:
					case IN_PROGRESS:
						if (retries > 0) {
							LOG.info("Requesting scan results from Watchtower");
							LOG.debug("Number of attempts remaining: " + retries);
							scanResult = getScanResult(scanResult.getTicket());
						} else {
							LOG.error("Scan has not completed within " + NUM_RETRIES * SLEEP_SECONDS
									+ " seconds. Scan ticket is '" + scanResult.getTicket() + "'");
						}
						break;
					default:
						LOG.warn("Unknown scan status in Watchtower response: " + scanStatus
								.getDisplayName());
						break;
				}
			}
			retries--;
		}
	}

	/**
	 * Reports the final results of the scan to the console or CSV file.
	 *
	 * @param output     the output location of the CSV results, if specified
	 * @param scanResult the final scan results
	 */
	private void reportScanResults(String output, UploadScanResult scanResult) {
		AbstractReporter reporter;
		if (StringUtils.isBlank(output)) {
			reporter = new ConsoleReporter();
		} else {
			reporter = new CsvReporter(output);
		}
		reporter.reportSummary(scanResult);
		reporter.report(scanResult);
	}

	/**
	 * Gets the scan result from Watchtower for the given scan ticket.
	 *
	 * @param ticket the scan ticket to retrieve results for
	 * @return the scan result from the Watchtower response
	 * @throws InterruptedException if there is a problem sleeping before the request is sent
	 */
	private UploadScanResult getScanResult(String ticket)
			throws InterruptedException {
		// Make sure the ticket is valid
		if (StringUtils.isBlank(ticket)) {
			LOG.error("Cannot get scan results for a blank scan ticket");
			return null;
		}
		LOG.info("Waiting before sending request");
		Thread.sleep(SLEEP_SECONDS * 1000);
		// Send request for updated scan status and results
		String serverUrl = params.getServerUrl();
		if (!serverUrl.endsWith("/")) {
			serverUrl += "/";
		}
		String url = serverUrl + UPLOAD_SCAN_ENDPOINT + "/" + ticket;
		HttpResponse<String> response = Unirest.get(url)
				.basicAuth(params.getApiKeyId(), params.getApiSecret()).asString();
		if (response.isSuccess()) {
			return GSON.fromJson(response.getBody(), UploadScanResult.class);
		} else {
			LOG.error("Received status code " + response.getStatus()
					+ " while trying to get scan results for ticket " + ticket);
			LOG.error(response.getBody());
			return null;
		}
	}
}
