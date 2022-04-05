package com.tracelink.appsec.module.advisory.scanner;

import java.util.List;
import java.util.stream.Collectors;

import com.tracelink.appsec.module.advisory.model.AdvisoryRuleDto;
import com.tracelink.appsec.watchtower.core.module.scanner.AbstractImageScanner;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.report.ScanViolation;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityFinding;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;

public class AdvisoryScanner extends AbstractImageScanner {

	@Override
	public ScanReport scan(ImageScanConfig config) {
		ScanReport report = new ScanReport();
		ImageSecurityReport imageReport = config.getImageReport();
		List<String> cves = config.getRuleset().getAllRules().stream()
				.filter(r -> (r instanceof AdvisoryRuleDto)).map(r -> (AdvisoryRuleDto) r)
				.map(AdvisoryRuleDto::getName).collect(Collectors.toList());
		for (ImageSecurityFinding finding : imageReport.getFindings()) {
			if (cves.contains(finding.getFindingName())) {
				ScanViolation sv = new ScanViolation();
				sv.setViolationName(finding.getFindingName());
				sv.setSeverity(finding.getSeverity().getName());
				sv.setSeverityValue(finding.getSeverity().getPriority());
				sv.setMessage(finding.getDescription());
				report.addViolation(sv);
			}
		}
		return report;
	}

	@Override
	public Class<? extends RuleDto> getSupportedRuleClass() {
		return AdvisoryRuleDto.class;
	}

}
