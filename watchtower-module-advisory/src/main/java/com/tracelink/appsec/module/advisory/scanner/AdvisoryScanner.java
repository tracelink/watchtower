package com.tracelink.appsec.module.advisory.scanner;

import java.util.List;
import java.util.stream.Collectors;

import com.tracelink.appsec.module.advisory.model.AdvisoryRuleDto;
import com.tracelink.appsec.watchtower.core.module.scanner.IImageScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityFinding;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanReport;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanViolation;

public class AdvisoryScanner implements IImageScanner {

	@Override
	public ImageScanReport scan(ImageScanConfig config) {
		ImageScanReport report = new ImageScanReport();
		RulesetDto ruleset = config.getRuleset();
		List<AdvisoryRuleDto> advisoryRules =
				ruleset.getAllRules().stream().filter(r -> (r instanceof AdvisoryRuleDto))
						.map(r -> (AdvisoryRuleDto) r).collect(Collectors.toList());

		for (ImageSecurityFinding finding : config.getSecurityReport().getFindings()) {
			if (advisoryRules.stream().noneMatch(r -> r.matches(finding))) {
				ImageScanViolation isv = new ImageScanViolation();
				isv.setDescription(finding.getDescription());
				isv.setFindingName(finding.getFindingName());
				isv.setPackageName(finding.getPackageName());
				isv.setScore(finding.getScore());
				isv.setSeverity(finding.getSeverity());
				isv.setUri(finding.getUri());
				isv.setVector(finding.getVector());
				report.addViolation(isv);
			}
		}

		return report;
	}

	@Override
	public Class<? extends RuleDto> getSupportedRuleClass() {
		return AdvisoryRuleDto.class;
	}

}
