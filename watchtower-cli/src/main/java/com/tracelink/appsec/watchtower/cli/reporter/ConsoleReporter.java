package com.tracelink.appsec.watchtower.cli.reporter;

import com.tracelink.appsec.watchtower.cli.scan.UploadScanResult;
import com.tracelink.appsec.watchtower.cli.scan.UploadScanResultViolation;
import java.util.List;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of the {@link AbstractReporter} that logs all violations and errors to the
 * console.
 *
 * @author mcool
 */
public class ConsoleReporter extends AbstractReporter {

	private static final Logger LOG = LoggerFactory.getLogger(ConsoleReporter.class);

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void report(UploadScanResult scanResult) {
		if (scanResult == null) {
			return;
		}
		LOG.info(fill(80));
		reportViolations(scanResult.getViolations());
		LOG.info(fill(20));
		reportErrors(scanResult.getErrorMessage());
		LOG.info(fill(80));
	}

	private void reportViolations(List<UploadScanResultViolation> violations) {
		if (violations == null || violations.isEmpty()) {
			LOG.info("No violations to report to console");
			return;
		}
		LOG.info("Violations");
		LOG.info(fill(20));

		for (UploadScanResultViolation violation : violations) {
			LOG.info("File Name:       " + violation.getFileName());
			LOG.info("Violation:       " + violation.getViolationName());
			LOG.info("Severity:        " + violation.getSeverity());
			LOG.info("Severity Value:  " + violation.getSeverityValue());
			LOG.info("Line Num:        " + violation.getLineNumber());
			LOG.info("Message:         " + violation.getMessage());
			LOG.info("External URL:    " + violation.getExternalUrl());
		}
	}

	private void reportErrors(String error) {
		if (StringUtils.isBlank(error)) {
			LOG.info("No errors to report to console");
			return;
		}
		LOG.info("Errors");
		LOG.info(fill(20));
		LOG.info(error);
	}
}
