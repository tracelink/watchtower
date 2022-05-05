package com.tracelink.appsec.watchtower.core.scan.code;

import java.nio.file.Path;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanConfig;

/**
 * Scan configuration object for Code Scanning
 *
 * @author csmith, mcool
 */
public class CodeScanConfig extends AbstractScanConfig {
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

}
