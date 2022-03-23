package com.tracelink.appsec.watchtower.core.scan.scm;

import java.nio.file.Path;

import com.tracelink.appsec.watchtower.core.scan.AbstractScanConfig;

public class ScmScanConfig extends AbstractScanConfig {
	protected Path workingDirectory;

	public void setWorkingDirectory(Path workingDirectory) {
		if (workingDirectory == null) {
			throw new IllegalArgumentException("Working directory cannot be null.");
		}
		this.workingDirectory = workingDirectory;
	}

	public Path getWorkingDirectory() {
		return this.workingDirectory;
	}
}
