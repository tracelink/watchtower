package com.tracelink.appsec.watchtower.core.scan.image;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanAgent;

@SuppressWarnings("unchecked")
public abstract class AbstractImageScanAgent<T extends AbstractImageScanAgent<T>>
		extends AbstractScanAgent<T> {
	private Logger LOG = LoggerFactory.getLogger(getClass());
	private ContainerImage image;
	private Collection<IScanner<ImageScanConfig>> scanners;

	public AbstractImageScanAgent(String scanName) {
		super(scanName);
	}

	/**
	 * Does initialization routines and checks to ensure parameters are correct
	 * 
	 * @throws ScanInitializationException if the scan cannot begin
	 */
	protected void initialize() throws ScanInitializationException {
		super.initialize();

		if (image == null) {
			throw new ScanInitializationException(
					"Image must be given for scan: " + getScanName());
		}

		if (scanners == null) {
			throw new ScanInitializationException(
					"Scanner(s) must be configured.");
		}
	}

	/**
	 * Set the scanners for this Agent's configuration
	 * 
	 * @param scanners the collection of scanners to use
	 * @return this agent
	 */
	public T withScanners(Collection<IScanner<ImageScanConfig>> scanners) {
		this.scanners = scanners;
		return (T) this;
	}

	public T withImage(ContainerImage image) {
		this.image = image;
		return (T) this;
	}

	protected ContainerImage getImage() {
		return image;
	}

	/**
	 * Performs individual scans of whatever is in the working directory, using the scanners
	 * configured for this agent.
	 * 
	 * @return list of reports from the scanner(s)
	 */
	@Override
	protected List<ScanReport> scan() {
		List<ScanReport> reports = new ArrayList<ScanReport>();

		// Create scan config
		ImageScanConfig config = getScanConfig();
		for (IScanner<ImageScanConfig> scanner : scanners) {
			if (config.getRuleset().getAllRules().stream().noneMatch(
					r -> scanner.getSupportedRuleClass() != null
							&& scanner.getSupportedRuleClass().isInstance(r))) {
				LOG.debug("No rules for scanner " + scanner.getClass().getSimpleName());
			} else {
				// Scan and format report
				ScanReport report = scanner.scan(config);
				if (config.isBenchmarkEnabled()) {
					report.logRuleBenchmarking();
				}
				reports.add(report);
			}
		}
		return reports;
	}

	protected abstract ImageScanConfig getScanConfig();

}
