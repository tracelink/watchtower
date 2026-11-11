package com.tracelink.appsec.module.checkov.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.watchtower.core.scan.code.ScannerFileTypes;

class CheckovScannerFileTypesTest {
	private final CheckovScanner scanner = new CheckovScanner(mock(CheckovEngine.class));

	@Test
	void defaultTypesCoverEveryFileCheckov2_0_257ParsedInTheProbe() {
		// Measured with checkov 2.0.257: these names were parsed into a framework.
		for (String parsed : new String[] {"main.tf", "k8s.yaml", "k8s2.yml", "cfn.template", "cfn.json",
				"arm.json", "serverless.yml", "Dockerfile"}) {
			assertThat(ScannerFileTypes.anyMatch(scanner.getDefaultFileTypes(), java.util.List.of("infra/" + parsed)))
					.as(parsed).isTrue();
		}
	}

	@Test
	void defaultTypesLeaveOutFilesCheckovIgnores() {
		for (String ignored : new String[] {"Containerfile", "cfn.txt", "README.md", "App.java"}) {
			assertThat(ScannerFileTypes.anyMatch(scanner.getDefaultFileTypes(), java.util.List.of(ignored)))
					.as(ignored).isFalse();
		}
	}
}
