package com.tracelink.appsec.watchtower.test;

import java.util.function.Consumer;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.AbstractScanReport;

/**
 * This Scan Config allows a tester to define a scanning configuration that will exercise the
 * scanner on a given resource file using a defined ruleset and provide the ability to check the
 * result against a number of Assertions
 * 
 * @author csmith
 *
 */
public class TestScanConfiguration<R extends AbstractScanReport, S> {
	private S scannerTarget;
	private RulesetDto ruleset;
	private Consumer<R> clause;

	public S getScannerTarget() {
		return this.scannerTarget;
	}

	/**
	 * Add a Resource file from /src/test/resources to this scan configuration. Note that this must
	 * be a simple file, not a file that needs unzipping or other transformation. This resource must
	 * also start with a '/' and be housed in the module's src/test/resources folder
	 * 
	 * @param scannerTarget the target for this config
	 * @return this builder
	 */
	public TestScanConfiguration<R, S> withScannerTarget(S scannerTarget) {
		this.scannerTarget = scannerTarget;
		return this;
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
	public TestScanConfiguration<R, S> withRuleset(RulesetDto ruleset) {
		this.ruleset = ruleset;
		return this;
	}

	public Consumer<R> getAssertClause() {
		return this.clause;
	}

	/**
	 * Provide a Consumer that will Assert the accuracy of the resulting
	 * {@linkplain AbstractScanReport} from the scanner.
	 * 
	 * @param clause the consumer clause that Asserts the correctness of the report
	 * @return this builder
	 */
	public TestScanConfiguration<R, S> withAssertClause(Consumer<R> clause) {
		this.clause = clause;
		return this;
	}
}
