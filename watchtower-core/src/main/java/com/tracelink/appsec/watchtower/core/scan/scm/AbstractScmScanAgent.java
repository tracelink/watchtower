package com.tracelink.appsec.watchtower.core.scan.scm;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
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
public abstract class AbstractScmScanAgent<T extends AbstractScmScanAgent<T>>
		extends AbstractScanAgent<T> {
	private Logger LOG = LoggerFactory.getLogger(getClass());

	private int threads;
	private Path workingDirectory;
	private Collection<IScanner<ScmScanConfig>> scanners;

	public AbstractScmScanAgent(String scanName) {
		super(scanName);
		this.workingDirectory = createWorkingDirectory();
	}

	/**
	 * Does initialization routines and checks to ensure parameters are correct
	 * 
	 * @throws ScanInitializationException if the scan cannot begin
	 */
	protected void initialize() throws ScanInitializationException {
		super.initialize();

		if (getWorkingDirectory() == null) {
			throw new ScanInitializationException(
					"Error creating working directory for scan: " + getScanName());
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
	public T withScanners(Collection<IScanner<ScmScanConfig>> scanners) {
		this.scanners = scanners;
		return (T) this;
	}

	protected ScmScanConfig getScanConfig() {
		ScmScanConfig config = new ScmScanConfig();
		config.setRuleset(getRuleset());
		config.setWorkingDirectory(getWorkingDirectory());
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
		ScmScanConfig config = getScanConfig();
		for (IScanner<ScmScanConfig> scanner : scanners) {
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
		} ;
		return reports;
	}

	/**
	 * Create a working directory
	 * 
	 * @return a Path to a working directory that this agent and scanners may use or null if an
	 *         exception occurred
	 */
	private Path createWorkingDirectory() {
		Path workingDirectory = null;
		try {
			workingDirectory =
					Files.createTempDirectory(getScanName()).toFile().getCanonicalFile()
							.getAbsoluteFile().toPath();
			Files.createDirectories(workingDirectory);
		} catch (IOException e) {
			LOG.error("Could not create working directory", e);
		}
		return workingDirectory;
	}

	/**
	 * Get the directory that this scan agent should scan against
	 * 
	 * @return a Path to a directory containing all data that should be scanned, or null if any
	 *         problem occurred
	 */
	public Path getWorkingDirectory() {
		return workingDirectory;
	}


}
