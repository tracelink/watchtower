package com.tracelink.appsec.watchtower.cli.reporter;

import com.tracelink.appsec.watchtower.cli.scan.UploadScanResult;
import com.tracelink.appsec.watchtower.cli.scan.UploadScanResultViolation;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of the {@link AbstractReporter} that logs all violations and errors to CSV files.
 * The location of the CSV files is determined by the output directory for this class.
 *
 * @author mcool
 */
public class CsvReporter extends AbstractReporter {

	private static final Logger LOG = LoggerFactory.getLogger(CsvReporter.class);

	private final Path outputPath;
	private Path reportLocation;
	private Path errorLocation;

	public CsvReporter(String output) {
		super(LOG);
		this.outputPath = Paths.get(output);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void report(UploadScanResult scanResult) {
		if (scanResult == null) {
			return;
		}

		try {
			configureOutputLocations(scanResult.getName());
			reportViolations(scanResult.getViolations());
			reportErrors(scanResult.getErrorMessage());
		} catch (IOException e) {
			LOG.error("Cannot report results to CSV", e);
		}
	}

	private void configureOutputLocations(String scanName) {
		Path report;
		Path error;
		if (outputPath.toFile().isFile()) {
			report = outputPath;
			String errorName = FilenameUtils.removeExtension(outputPath.getFileName().toString())
					+ "-errors.csv";
			error = outputPath.getParent().resolve(errorName);
		} else {
			String scanNameNoExtension = FilenameUtils.removeExtension(scanName);
			report = outputPath.resolve(scanNameNoExtension + "-report.csv");
			error = outputPath.resolve(scanNameNoExtension + "-errors.csv");
		}

		this.reportLocation = report.toAbsolutePath();
		this.errorLocation = error.toAbsolutePath();
	}

	private void reportViolations(List<UploadScanResultViolation> violations)
			throws IOException {
		if (violations == null || violations.isEmpty()) {
			LOG.info("No violations to report to CSV");
			return;
		}

		try (CSVPrinter reportWriter = new CSVPrinter(Files.newBufferedWriter(reportLocation),
				CSVFormat.DEFAULT.withHeader("File Name", "Violation", "Severity", "Severity Value",
						"Line Num", "Message", "External URL"))) {
			for (UploadScanResultViolation violation : violations) {
				reportWriter.printRecord(violation.getFileName(), violation.getViolationName(),
						violation.getSeverity(), violation.getSeverityValue(),
						violation.getLineNumber(), violation.getMessage(),
						violation.getExternalUrl());
			}
		}
	}

	private void reportErrors(String error) throws IOException {
		if (StringUtils.isBlank(error)) {
			LOG.info("No errors to report to CSV");
			return;
		}

		try (CSVPrinter errorWriter = new CSVPrinter(Files.newBufferedWriter(errorLocation),
				CSVFormat.DEFAULT.withHeader("Error Message"))) {
			errorWriter.printRecord(error);
		}
	}
}
