package com.tracelink.appsec.watchtower.core.scan.code;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanAgent;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanningService;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

/**
 * Handles orchestration of individual scanners for scans of an SCM pull request. This class is
 * executed by one of the {@link AbstractScanningService}s.
 * <p>
 * Ensures that all objects are initialized and executes scanners against a working directory.
 * Collects reports and sends to the report method for implementations to manage. Finally, reports
 * on benchmarks, if configured and then starts a cleanup procedure for implementations
 *
 * @author csmith, mcool
 * @param <T> The type of {@link AbstractCodeScanAgent} (for builder subclassing)
 */
public abstract class AbstractCodeScanAgent<T extends AbstractCodeScanAgent<T>>
		extends
		AbstractScanAgent<T, ICodeScanner, CodeScanConfig, CodeScanReport> {
	private Logger LOG = LoggerFactory.getLogger(getClass());

	private int threads;
	private Path workingDirectory;

	public AbstractCodeScanAgent(String scanName) {
		super(scanName);
		workingDirectory = createWorkingDirectory();
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

		if (threads < 0) {
			throw new ScanInitializationException(
					"Threads must be 0 or greater");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected CodeScanConfig createScanConfig() {
		// Create scan config
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(getRuleset());
		config.setWorkingDirectory(getWorkingDirectory());
		config.setThreads(threads);
		config.setBenchmarkEnabled(isBenchmarkingEnabled());
		return config;
	}

	/**
	 * Create a working directory
	 * 
	 * @return a Path to a working directory that this agent and scanners may use or null if an
	 *         exception occurred
	 */
	protected Path createWorkingDirectory() {
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
		return this.workingDirectory;
	}

	/**
	 * Do any necessary reporting given the raw reports from the scanners
	 * 
	 * @param reports a list of reports given by the scanners
	 */
	protected abstract void report(List<CodeScanReport> reports);


	/**
	 * Do any cleanup necessary to close this scan agent. This always runs.
	 */
	protected abstract void clean();
}
