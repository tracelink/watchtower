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
import com.tracelink.appsec.watchtower.core.scan.api.image.ecr.EcrImage;

@SuppressWarnings("unchecked")
public abstract class AbstractImageScanAgent<T extends AbstractImageScanAgent<T>>
		extends AbstractScanAgent<T> {
	private Logger LOG = LoggerFactory.getLogger(getClass());
	private EcrImage image;
	private int threads;
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

		if (threads < 0) {
			throw new ScanInitializationException(
					"Threads must be 0 or greater");
		}
	}

	/**
	 * Set the number of sub-threads this Agent can use
	 * <p>
	 * 0 means this is a single-threaded agent
	 * <p>
	 * 1 means this agent may use 1 additional thread, etc
	 * 
	 * @param threads the number of additional threads to use
	 * @return this agent
	 */
	public T withThreads(int threads) {
		this.threads = threads;
		return (T) this;
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

	public T withImage(EcrImage image) {
		this.image = image;
		return (T) this;
	}

	public EcrImage getImage() {
		return image;
	}

	protected ImageScanConfig getScanConfig() {
		ImageScanConfig config = new ImageScanConfig();
		config.setRuleset(getRuleset());
		config.setImage(image);
		config.setThreads(threads);
		config.setBenchmarkEnabled(getBenchmarking().isEnabled());
		return config;
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
}
