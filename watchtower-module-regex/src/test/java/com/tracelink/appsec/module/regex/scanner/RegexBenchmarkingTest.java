package com.tracelink.appsec.module.regex.scanner;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.tracelink.appsec.module.regex.model.RegexRuleDto;
import com.tracelink.appsec.watchtower.core.benchmark.Benchmarker;

@ExtendWith(MockitoExtension.class)
public class RegexBenchmarkingTest {

	@Mock
	RegexRuleDto rule;

	@Test
	public void testOutputForRules() throws Exception {
		RegexBenchmarking rb = new RegexBenchmarking();
		String ruleName = "TestRuleName";

		BDDMockito.given(rule.getName()).willReturn(ruleName);

		rb.enable(true);
		try (Benchmarker bmrkr = rb.newRuleBenchmarker(rule)) {

		}

		StringBuilder sb = new StringBuilder();
		rb.outputRuleTimers("", sb);
		String output = sb.toString();
		Assertions.assertTrue(output.contains(ruleName));
	}

}
