package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.module.scanner.IImageScanner;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanAgent;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;
import com.tracelink.appsec.watchtower.core.scan.image.api.IImageApi;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanError;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanReport;

public class ImageScanAgent extends
		AbstractScanAgent<ImageScanAgent, IImageScanner, ImageScanConfig, ImageScanReport> {
	private Logger LOG = LoggerFactory.getLogger(getClass());

	private ImageScan scan;

	private IImageApi api;

	private ImageScanResultService scanResultService;

	private long startTime;

	public ImageScanAgent(ImageScan scan) {
		super(scan.getScanName());
		this.scan = scan;
	}

	public ImageScanAgent withApi(IImageApi api) {
		this.api = api;
		return this;
	}

	public ImageScanAgent withScanResultService(ImageScanResultService scanResultService) {
		this.scanResultService = scanResultService;
		return this;
	}

	protected void initialize() throws ScanInitializationException {
		this.startTime = System.currentTimeMillis();
		super.initialize();
		if (api == null) {
			throw new ScanInitializationException("API must be configured");
		}
		if (scanResultService == null) {
			throw new ScanInitializationException("Scan Result Service must be configured");
		}
	}

	protected ImageScanConfig createScanConfig() {
		// Create scan config
		ImageScanConfig config = new ImageScanConfig();
		config.setRuleset(getRuleset());
		config.setScan(scan);
		config.setSecurityReport(api.getSecurityReportForImage(scan));
		config.setBenchmarkEnabled(isBenchmarkingEnabled());
		return config;
	}

	protected void report(List<ImageScanReport> reports) {
		List<ImageViolationEntity> violations = new ArrayList<>();
		List<ImageScanError> errors = new ArrayList<>();
		for (ImageScanReport report : reports) {
			report.getViolations().stream().forEach(sv -> {
				AdvisoryEntity advisory =
						this.scanResultService.getOrCreateAdvisory(sv);
				ImageViolationEntity violation = new ImageViolationEntity(sv, advisory);
				RulesetDto ruleset = getRuleset();
				if (ruleset.getBlockingLevel() != null) {
					violation.setBlocking(
							sv.getSeverity().compareTo(ruleset.getBlockingLevel()) <= 0);
				}
				violations.add(violation);
			});
			errors.addAll(report.getErrors());
		}

		Collections.sort(violations);

		reportViaApi(violations, errors);

		scanResultService.saveImageReport(scan, startTime, violations, errors);
	}

	private void reportViaApi(List<ImageViolationEntity> violations, List<ImageScanError> errors) {
		if (violations.stream().anyMatch(v -> v.isBlocking())) {
			api.rejectImage(scan, violations);
		}
		if (!errors.isEmpty()) {
			logErrors(errors);
		}
	}

	private void logErrors(List<ImageScanError> errors) {
		StringBuilder sb = new StringBuilder();
		sb.append("Errors found during scan: " + this.getScanName() + '\n');
		for (ImageScanError err : errors) {
			sb.append("--" + err.getErrorMessage() + '\n');
		}
		LOG.debug(sb.toString());
	}

	@Override
	protected void clean() {
		// Unused
	}
}
