package com.tracelink.appsec.module.pmd.scanner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.pmd.service.PMDRuleService;

class PMDScannerFileTypesTest {
	@Test
	void defaultTypesAreTheExtensionsOfTheLanguagesPmdAnalyses() {
		// Java, Scala and XML are the languages Watchtower enables (PMDLanguageSupport), as PMD 7.27 registers them.
		assertThat(new PMDScanner(mock(PMDRuleService.class)).getDefaultFileTypes())
				.containsExactly(".java", ".scala", ".xml");
	}
}
