package com.tracelink.appsec.watchtower.test;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Assertions;

import com.tracelink.appsec.watchtower.core.scan.scm.ScmScanConfig;

public class ScmTestScanConfiguration
		extends AbstractTestScanConfiguration<ScmTestScanConfiguration, ScmScanConfig> {

	@Override
	public ScmScanConfig getScanConfig() {
		try {
			Path testDir = Files.createTempDirectory(null);
			Path testFile = testDir.resolve(Paths.get(getResourceFile()).getFileName());

			try (InputStream is =
					getClass().getResourceAsStream(getResourceFile());
					FileOutputStream fos = new FileOutputStream(testFile.toFile())) {
				IOUtils.copy(is, fos);
			}
			Assertions.assertTrue(testFile.toFile().exists());
			ScmScanConfig config = new ScmScanConfig();
			config.setBenchmarkEnabled(false);
			config.setDebugEnabled(false);
			config.setRuleset(getRuleset());
			config.setThreads(0);
			config.setWorkingDirectory(testDir);
			return config;
		} catch (Exception e) {
			return null;
		}
	}
}
