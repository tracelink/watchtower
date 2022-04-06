package com.tracelink.appsec.watchtower.core.scan.image.service;

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
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanReport;

public class ImageScanAgent extends
		AbstractScanAgent<ImageScanAgent, IImageScanner, ImageScanConfig, ImageScanReport> {
	private Logger LOG = LoggerFactory.getLogger(getClass());

	private ImageScan scan;
	private RulesetDto ruleset;

	private IImageApi api;

	public ImageScanAgent(ImageScan scan) {
		super(scan.getScanName());
		this.scan = scan;
	}

	public ImageScanAgent withApi(IImageApi api) {
		this.api = api;
		return this;
	}

	protected void initialize() throws ScanInitializationException {
		super.initialize();
		if (api == null) {
			throw new ScanInitializationException("API must be configured");
		}
	}

	protected ImageScanConfig createScanConfig() {
		// Create scan config
		ImageScanConfig config = new ImageScanConfig();
		config.setRuleset(ruleset);
		config.setScan(scan);
		config.setSecurityReport(api.getSecurityReportForImage(scan));
		config.setBenchmarkEnabled(isBenchmarkingEnabled());
		return config;
	}

	protected void report(List<ImageScanReport> reports) {
		// TODO Auto-generated method stub

	}

	@Override
	protected void clean() {

	}

}
