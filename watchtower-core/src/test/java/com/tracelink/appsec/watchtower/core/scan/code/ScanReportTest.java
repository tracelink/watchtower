package com.tracelink.appsec.watchtower.core.scan.code;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.benchmark.Benchmarking;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;


@ExtendWith(SpringExtension.class)
public class ScanReportTest {

	@Test
	public void testDAO() {
		CodeScanReport report = new CodeScanReport();

		String error = "This is an error";
		report.addError(new CodeScanError(error));
		Assertions.assertEquals(error, report.getErrors().get(0).getErrorMessage());

		String violation = "this is a violation";
		CodeScanViolation vio = new CodeScanViolation();
		vio.setMessage(violation);
		report.addViolation(vio);
		Assertions.assertEquals(violation, report.getViolations().get(0).getMessage());

		CodeScanReport report2 = new CodeScanReport();
		report2.addError(new CodeScanError(error));
		report2.addViolation(vio);
		report.join(report2);
		Assertions.assertEquals(2, report.getErrors().size());
		Assertions.assertEquals(2, report.getViolations().size());

		Benchmarking<RuleDto> ruleBench = BDDMockito.mock(Benchmarking.class);
		report.logRuleBenchmarking();
		BDDMockito.verify(ruleBench, BDDMockito.never()).report(BDDMockito.anyString());
		report.setRuleBenchmarking(ruleBench);
		report.logRuleBenchmarking();
		BDDMockito.verify(ruleBench).report(BDDMockito.anyString());


	}
}
