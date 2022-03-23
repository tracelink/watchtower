package com.tracelink.appsec.watchtower.test;

import java.util.function.Consumer;

import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanConfig;

/**
 * This Scan Config allows a tester to define a scanning configuration that will exercise the
 * scanner on a given resource file using a defined ruleset and provide the ability to check the
 * result against a number of Assertions
 * 
 * @author csmith
 *
 */
public class AbstractTestScanConfiguration<T extends AbstractTestScanConfiguration<T, C>, C extends AbstractScanConfig> {
	private String resourceFile;
	private RulesetDto ruleset;
	private Consumer<ScanReport> clause;
	private C config;

	public String getResourceFile() {
		return this.resourceFile;
	}

	/**
	 * Add a Resource file from /src/test/resources to this scan configuration. Note that this must
	 * be a simple file, not a file that needs unzipping or other transformation. This resource must
	 * also start with a '/' and be housed in the module's src/test/resources folder
	 * 
	 * @param resource the resource file to use
	 * @return this builder
	 */
	public T withTargetResourceFile(String resource) {
		resourceFile = resource;
		return (T) this;
	}

	public RulesetDto getRuleset() {
		return this.ruleset;
	}

	/**
	 * Add a Ruleset definition to this scan configuration. This ruleset contains the rules that
	 * will be run by the scanner on the resource file.
	 * 
	 * @param ruleset the ruleset to use
	 * @return this builder
	 */
	public T withRuleset(RulesetDto ruleset) {
		this.ruleset = ruleset;
		return (T) this;
	}

	public Consumer<ScanReport> getAssertClause() {
		return this.clause;
	}

	/**
	 * Provide a Consumer that will Assert the accuracy of the resulting {@linkplain ScanReport}
	 * from the scanner.
	 * 
	 * @param clause the consumer clause that Asserts the correctness of the report
	 * @return this builder
	 */
	public T withAssertClause(Consumer<ScanReport> clause) {
		this.clause = clause;
		return (T) this;
	}

	public T withScanConfig(C config) {
		this.config = config;
		return (T) this;
	}

	public C getScanConfig() {
		return config;
	}
}
