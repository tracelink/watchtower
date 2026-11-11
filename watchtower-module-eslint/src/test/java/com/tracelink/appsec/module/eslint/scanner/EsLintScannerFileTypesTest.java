package com.tracelink.appsec.module.eslint.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.eslint.engine.LinterEngine;

class EsLintScannerFileTypesTest {
	@Test
	void defaultTypesAreTheScriptFilesTheBridgeCanParse() {
		// The bridge hands every file to node and reports a parse error for anything that is not
		// JavaScript, so it must not be given other files by default.
		assertThat(new EsLintScanner(mock(LinterEngine.class)).getDefaultFileTypes())
				.containsExactly(".js", ".cjs", ".mjs");
	}
}
