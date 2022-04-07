package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.ArrayList;
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


	}

	@Override
	protected void clean() {

	}


}
