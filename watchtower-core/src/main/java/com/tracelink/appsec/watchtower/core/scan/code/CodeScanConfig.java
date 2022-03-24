package com.tracelink.appsec.watchtower.core.scan.code;

import java.nio.file.Path;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanConfig;

public class CodeScanConfig extends AbstractScanConfig {
	protected Path workingDirectory;
	/**
	 * number of threads to be used by this scan
	 */
	private int threads = Runtime.getRuntime().availableProcessors();

	public void setWorkingDirectory(Path workingDirectory) {
		if (workingDirectory == null) {
			throw new IllegalArgumentException("Working directory cannot be null.");
		}
		this.workingDirectory = workingDirectory;
	}

	public Path getWorkingDirectory() {
		return this.workingDirectory;
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
}
