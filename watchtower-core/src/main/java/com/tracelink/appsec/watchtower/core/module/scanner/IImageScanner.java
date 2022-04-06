package com.tracelink.appsec.watchtower.core.module.scanner;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanReport;

public interface IImageScanner extends IScanner<ImageScanConfig, ImageScanReport> {
	/**
	 * Return a report of this scan
	 *
	 * @param config the config to provide info for the scan
	 * @return the report generated by this scan, never null
	 */
	ImageScanReport scan(ImageScanConfig config);

	/**
	 * Get the rule class that this scanner supports
	 * 
	 * @return the {@link RuleDto} rule class that this scanner can handle
	 */
	Class<? extends RuleDto> getSupportedRuleClass();
}