package com.tracelink.appsec.module.cve.scanner;

import com.tracelink.appsec.watchtower.core.module.scanner.AbstractImageScanner;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;

public class CveScanner extends AbstractImageScanner {

	@Override
	public ScanReport scan(ImageScanConfig config) {

		return null;
	}

	@Override
	public Class<? extends RuleDto> getSupportedRuleClass() {
		// TODO Auto-generated method stub
		return null;
	}

}
