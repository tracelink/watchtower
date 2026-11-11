package com.tracelink.appsec.watchtower.core.module.scanner;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

public class ICodeScannerTest {

	private static final ICodeScanner DEFAULT_SCANNER = new ICodeScanner() {
		@Override
		public CodeScanReport scan(CodeScanConfig config) {
			return new CodeScanReport();
		}

		@Override
		public List<Class<? extends RuleDto>> getSupportedRuleClass() {
			return Collections.emptyList();
		}
	};

	@Test
	public void testDefaultScannerContract() {
		Assertions.assertFalse(DEFAULT_SCANNER.isSensitive());
		Assertions.assertEquals(ScanScope.CHANGED_FILES, DEFAULT_SCANNER.getRequiredScope());
		Assertions.assertTrue(DEFAULT_SCANNER.getRequiredFilePatterns().isEmpty());
		Assertions.assertArrayEquals(new ScanScope[] {ScanScope.CHANGED_FILES,
				ScanScope.MANIFEST_FILES, ScanScope.FULL_SOURCE}, ScanScope.values());
		for (ScanScope scope : ScanScope.values()) {
			Assertions.assertEquals(scope, ScanScope.valueOf(scope.name()));
		}
		Assertions.assertFalse(DEFAULT_SCANNER.getExecutionIdentity(new CodeScanConfig()).isReusable());
		Assertions.assertEquals(Set.of("test", "node_modules"),
				DEFAULT_SCANNER.getExcludedFolders());
		Assertions.assertEquals(ICodeScanner.DEFAULT_EXCLUDED_FOLDERS,
				DEFAULT_SCANNER.getExcludedFolders());
		Assertions.assertThrows(UnsupportedOperationException.class,
				() -> ICodeScanner.DEFAULT_EXCLUDED_FOLDERS.add("src"));
	}
}
