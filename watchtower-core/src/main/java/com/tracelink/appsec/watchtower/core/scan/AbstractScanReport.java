package com.tracelink.appsec.watchtower.core.scan;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.tracelink.appsec.watchtower.core.benchmark.Benchmarking;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/**
 * The abstract report for any scan.
 *
 * @author csmith, mcool
 */
public class AbstractScanReport {
	private static final Logger LOG = LoggerFactory.getLogger(AbstractScanReport.class);

	private Benchmarking<? extends RuleDto> ruleBenchmarking;

	public void setRuleBenchmarking(Benchmarking<? extends RuleDto> ruleBenchmarking) {
		this.ruleBenchmarking = ruleBenchmarking;
	}

	/**
	 * log any benchmarking results if there are any. Only called if config is set for benchmarking
	 */
	public void logRuleBenchmarking() {
		if (ruleBenchmarking != null) {
			LOG.info(ruleBenchmarking.report("\n"));
		}
	}

}
