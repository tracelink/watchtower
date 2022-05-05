package com.tracelink.appsec.module.checkov.scanner;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

@ExtendWith(SpringExtension.class)
public class CheckovScannerTest {

	@Mock
	private CheckovEngine engine;

	@Test
	public void testScanException() {
		CheckovScanner scanner = new CheckovScanner(engine);
		CodeScanReport report = scanner.scan(new CodeScanConfig());
		MatcherAssert.assertThat(report.getErrors(), Matchers.hasSize(1));
		MatcherAssert.assertThat(report.getErrors().get(0).getErrorMessage(),
				Matchers.containsString("Error while scanning"));
	}
}
