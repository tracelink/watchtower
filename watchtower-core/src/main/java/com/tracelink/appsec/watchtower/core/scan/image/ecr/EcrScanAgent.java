package com.tracelink.appsec.watchtower.core.scan.image.ecr;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.report.ScanError;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.api.image.ecr.EcrApi;
import com.tracelink.appsec.watchtower.core.scan.image.AbstractImageScanAgent;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScanConfig;
import com.tracelink.appsec.watchtower.core.scan.image.ecr.entity.EcrViolationEntity;

public class EcrScanAgent extends AbstractImageScanAgent<EcrScanAgent> {
	private static Logger LOG = LoggerFactory.getLogger(EcrScanAgent.class);
	private EcrApi api;
	private EcrScanResultService ecrScanResultService;
	private long startTime;

	public EcrScanAgent(String scanName) {
		super(scanName);
	}

	public EcrScanAgent withApi(EcrApi api) {
		this.api = api;
		return this;
	}

	/**
	 * Set the {@linkplain EcrScanResultService} for this Agent's configuration
	 * 
	 * @param ecrScanResultService the result Service to use
	 * @return this agent
	 */
	public EcrScanAgent withScanResultService(EcrScanResultService ecrScanResultService) {
		this.ecrScanResultService = ecrScanResultService;
		return this;
	}

	/**
	 * {@inheritDoc}
	 */
	protected void initialize() throws ScanInitializationException {
		super.initialize();
		this.startTime = System.currentTimeMillis();

		if (api == null) {
			throw new ScanInitializationException("API must be configured.");
		}
		if (ecrScanResultService == null) {
			throw new ScanInitializationException("Results Service must be configured.");
		}
	}

	@Override
	protected ImageScanConfig getScanConfig() {
		ImageScanConfig config = new ImageScanConfig();
		config.setRuleset(getRuleset());
		config.setImageReport(api.getSecurityReportForImage(getImage()));
		config.setBenchmarkEnabled(getBenchmarking().isEnabled());
		return config;
	}

	@Override
	protected void report(List<ScanReport> reports) {
		List<EcrViolationEntity> violations = new ArrayList<>();
		List<ScanError> errors = new ArrayList<>();

		for (ScanReport report : reports) {
			report.getViolations().stream().forEach(sv -> {
				EcrViolationEntity violation = new EcrViolationEntity();
				RulesetDto ruleset = getRuleset();
				if (ruleset.getBlockingLevel() != null) {
					violation.setBlocking(RulePriority.valueOf(sv.getSeverityValue())
							.compareTo(ruleset.getBlockingLevel()) <= 0);
				}
				violations.add(violation);
			});
			errors.addAll(report.getErrors());
		}
		violations.sort(null);

		reportToEcr(violations, errors);

		ecrScanResultService.saveReport(getImage(), startTime, violations, errors);
	}

	private void reportToEcr(List<EcrViolationEntity> violations, List<ScanError> errors) {
		if (violations.stream().anyMatch(v -> v.isBlocking())) {
			api.rejectImage(getImage());
		}
		if (!errors.isEmpty()) {
			logErrors(errors);
		}
	}

	/**
	 * If there are any errors, this method will execute. Default implementation is to log to the
	 * debug log
	 * 
	 * @param errors the list of errors to log
	 */
	private void logErrors(List<ScanError> errors) {
		StringBuilder sb = new StringBuilder();
		sb.append("Errors found during scan: " + getImage().getImageName() + '\n');
		for (ScanError err : errors) {
			sb.append("--" + err.getErrorMessage() + '\n');
		}
		LOG.debug(sb.toString());
	}

	@Override
	protected void clean() {

	}
}
