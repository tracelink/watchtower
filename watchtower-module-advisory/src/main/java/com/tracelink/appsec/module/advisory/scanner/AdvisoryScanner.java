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

/**
 * Scanner implementation for Advisory Rules. The Scanner will parse an {@linkplain ImageScanReport}
 * to identify findings that fail Advisory Rules.
 * 
 * @author csmith
 *
 */
public class AdvisoryScanner implements IImageScanner {

	@Override
	public ImageScanReport scan(ImageScanConfig config) {
		ImageScanReport report = new ImageScanReport();
		report.setScanTimedOut(config.getSecurityReport().getScanTimedOut());
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
