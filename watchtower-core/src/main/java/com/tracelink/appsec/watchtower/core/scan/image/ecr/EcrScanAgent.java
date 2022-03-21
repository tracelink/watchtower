package com.tracelink.appsec.watchtower.core.scan.image.ecr;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.scm.IScmApi;

public class EcrScanAgent implements Runnable {
	private static Logger LOG = LoggerFactory.getLogger(EcrScanAgent.class);
	private EcrImage image;
	private EcrApi api;
	private EcrScanResultService ecrScanResultService;
	private long startTime;
	private String scanName;
	private RulesetDto ruleset;

	public EcrScanAgent(EcrImage image) {
		this.scanName = image.getImageName();
		this.image = image;
	}

	/**
	 * Set the {@linkplain IScmApi} for this Agent's configuration to interact with Pull Request
	 * SCMs
	 * 
	 * @param api the api to use
	 * @return this agent
	 */
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
	 * Set the ruleset for this Agent's configuration
	 * 
	 * @param ruleset the ruleset to use
	 * @return this agent
	 */
	public EcrScanAgent withRuleset(RulesetDto ruleset) {
		this.ruleset = ruleset;
		return this;
	}

	@Override
	public void run() {
		try {
			LOG.info("Starting Scan for scan: " + scanName);
			initialize();
			scan();
			LOG.info("Report complete for scan: " + scanName);
		} catch (Exception e) {
			LOG.error("Exception while scanning. Scan Name: " + scanName, e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	protected void initialize() throws ScanInitializationException {
		this.startTime = System.currentTimeMillis();
		if (ruleset == null) {
			throw new ScanInitializationException("Ruleset must be configured");
		}
		if (api == null) {
			throw new ScanInitializationException("API must be configured.");
		}
		if (ecrScanResultService == null) {
			throw new ScanInitializationException("Results Service must be configured.");
		}
	}

	protected void scan() {
		EcrSecurityReport securityReport = api.getSecurityReportForImage(image);

		EcrSecurityReport filteredSecurityReport = securityReport.filterByAllowList(ruleset);

		if (filteredSecurityReport.shouldBlock()) {
			api.rejectImage(image);
		}

		ecrScanResultService.saveReport(image, filteredSecurityReport, startTime);
	}
}
