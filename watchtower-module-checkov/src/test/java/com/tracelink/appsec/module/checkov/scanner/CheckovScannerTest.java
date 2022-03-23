package com.tracelink.appsec.module.checkov.scanner;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.scan.scm.ScmScanConfig;

@ExtendWith(SpringExtension.class)
public class CheckovScannerTest {

	@Mock
	private CheckovEngine engine;

	@Test
	public void testScanException() {
		CheckovScanner scanner = new CheckovScanner(engine);
		ScanReport report = scanner.scan(new ScmScanConfig());
		MatcherAssert.assertThat(report.getErrors(), Matchers.hasSize(1));
		MatcherAssert.assertThat(report.getErrors().get(0).getErrorMessage(),
				Matchers.containsString("Error while scanning"));
	}
}
