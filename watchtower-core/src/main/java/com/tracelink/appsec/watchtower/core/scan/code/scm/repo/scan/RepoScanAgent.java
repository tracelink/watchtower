package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.scan;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.List;

import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.exception.ScanInitializationException;
import com.tracelink.appsec.watchtower.core.scan.ScanExecutionSummary;
import com.tracelink.appsec.watchtower.core.scan.code.AbstractCodeScanAgent;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.SourceTreeCleaner;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;

/**
 * Scans a whole repository at one commit: downloads it into this pod's temporary working
 * directory, trims what no scanner reads, runs every scanner the ruleset has rules for, hands
 * the results to a sink while the code is still on disk, and always deletes the directory.
 * Nothing it downloads is cached or kept.
 *
 * @author Watchtower
 */
public class RepoScanAgent extends AbstractCodeScanAgent<RepoScanAgent> {

	private static final Logger LOG = LoggerFactory.getLogger(RepoScanAgent.class);

	/** Prefix of every repository scan's working directory, so leftovers can be found. */
	public static final String WORKING_DIRECTORY_PREFIX = "reposcan-";

	private final IScmApi api;

	private final String repository;

	private final String commitHash;

	private final ReportSink sink;
	private final long scanId;

	private Exception failure;

	public RepoScanAgent(long scanId, IScmApi api, String repository, String commitHash,
			ReportSink sink) {
		super(WORKING_DIRECTORY_PREFIX + scanId);
		this.scanId = scanId;
		this.api = api;
		this.repository = repository;
		this.commitHash = commitHash;
		this.sink = sink;
	}

	@Override
	protected void initialize() throws ScanInitializationException {
		super.initialize();
		try {
			api.downloadSource(repository, commitHash, getWorkingDirectory());
			SourceTreeCleaner.clean(getWorkingDirectory(), determineExcludedFolders());
		} catch (IOException e) {
			throw new ScanInitializationException("Could not download " + repository, e);
		}
	}

	@Override
	protected CodeScanConfig createScanConfig() {
		CodeScanConfig config = super.createScanConfig();
		// Scopes repository-level allowlists, such as the secrets allowlist
		config.setRepositoryName(repository);
		return config;
	}

	@Override
	protected String getMetricType() {
		return "repository";
	}

	@Override
	protected void report(List<CodeScanReport> reports) {
		try {
			sink.accept(reports, getWorkingDirectory(), getExecutionSummary());
			recordShadowComparison("repository", scanId);
		} catch (IOException e) {
			throw new UncheckedIOException(e);
		}
	}

	@Override
	protected void handleScanException(Exception e) {
		this.failure = e;
		LOG.warn("Repository scan " + getScanName() + " failed: " + e.getMessage());
	}

	@Override
	protected void clean() {
		FileUtils.deleteQuietly(getWorkingDirectory().toFile());
	}

	/**
	 * @return why the scan failed, or null if it did not
	 */
	public Exception getFailure() {
		return failure;
	}

	public ScanExecutionSummary executionSummary() {
		return getExecutionSummary();
	}

	/**
	 * Receives a scan's results while its working directory still exists.
	 */
	@FunctionalInterface
	public interface ReportSink {
		void accept(List<CodeScanReport> reports, Path workingDirectory,
				ScanExecutionSummary summary) throws IOException;
	}
}
