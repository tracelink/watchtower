package com.tracelink.appsec.watchtower.core.scan.code;

import java.nio.file.Path;
import java.util.Collections;
import java.util.Set;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanConfig;

/**
 * Scan configuration object for Code Scanning
 *
 * @author csmith, mcool
 */
public class CodeScanConfig extends AbstractScanConfig {
	private ScanExecutionContext executionContext;
	public ScanExecutionContext getExecutionContext() { return executionContext; }
	public void setExecutionContext(ScanExecutionContext context) { executionContext = context; }
	/**
	 * path to the working directory, which contains files to be scanned
	 */
	private Path workingDirectory;
	/**
	 * number of threads to be used by this scan
	 */
	private int threads = Runtime.getRuntime().availableProcessors();
	/**
	 * whether debug is enabled for this scan
	 */
	private boolean debugEnabled = false;
	/**
	 * Paths, relative to {@link #workingDirectory}, of files that were changed in the pull
	 * request this scan is for. Empty for scan types with no pull request (e.g. uploads) or
	 * when the scan agent has not populated it. A scanner that needs finer-grained control than
	 * its declared {@code ScanScope} provides may consult this; scanners that ignore it see the
	 * existing behaviour of scanning everything present in the working directory.
	 */
	private Set<String> changedFilePaths = Collections.emptySet();
	/**
	 * Name of the repository being scanned, for repository-scoped scanner settings. Null for
	 * scan types with no repository (e.g. uploads).
	 */
	private String repositoryName;
	/**
	 * File types of the scanner currently being run (see {@link ScannerFileTypes}); empty means every
	 * file. Set by the scan agent for each scanner, so a scanner that walks the working directory
	 * can leave other files alone.
	 */
	private java.util.List<String> fileTypes = java.util.Collections.emptyList();

	public java.util.List<String> getFileTypes() {
		return fileTypes;
	}

	public void setFileTypes(java.util.List<String> fileTypes) {
		this.fileTypes = fileTypes == null ? java.util.Collections.emptyList() : java.util.List.copyOf(fileTypes);
	}

	public String getRepositoryName() {
		return repositoryName;
	}

	public void setRepositoryName(String repositoryName) {
		this.repositoryName = repositoryName;
	}

	public Path getWorkingDirectory() {
		return workingDirectory;
	}

	public void setWorkingDirectory(Path workingDirectory) {
		if (workingDirectory == null) {
			throw new IllegalArgumentException("Working directory cannot be null.");
		}
		this.workingDirectory = workingDirectory;
	}

	public int getThreads() {
		return threads;
	}

	public void setThreads(int threads) {
		if (threads < 0) {
			throw new IllegalArgumentException("Threads cannot be negative. Threads: " + threads);
		}
		this.threads = threads;
	}

	public boolean isDebugEnabled() {
		return debugEnabled;
	}

	public void setDebugEnabled(boolean debugEnabled) {
		this.debugEnabled = debugEnabled;
	}

	public Set<String> getChangedFilePaths() {
		return changedFilePaths;
	}

	public void setChangedFilePaths(Set<String> changedFilePaths) {
		this.changedFilePaths =
				changedFilePaths == null ? Collections.emptySet() : changedFilePaths;
	}

}
