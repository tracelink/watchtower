package com.tracelink.appsec.watchtower.test;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Supplier;

import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

/**
 * The TestBuilder allows Scanner Module authors to supply a few expected values for their module so
 * that the overall test harness {@link ScannerModuleTest} can work
 *
 * @author csmith
 */
public class ScannerModuleTestBuilder {

	private String name;
	private String schemaName;
	private String migration;
	private Class<? extends RuleDto> supportedRuleClass;
	private Supplier<? extends RuleDto> ruleSupplier;
	private final Set<ScannerModuleTestOption> ignoredOptions = new HashSet<>();
	private TestScanConfiguration testScanConfig;

	public String getName() {
		return name;
	}

	/**
	 * The name of the module
	 *
	 * @param name the module name
	 * @return this builder
	 */
	public ScannerModuleTestBuilder withName(String name) {
		this.name = name;
		return this;
	}

	public String getSchemaName() {
		return schemaName;
	}

	/**
	 * the name of the schema history table
	 *
	 * @param schemaName schema history table name
	 * @return this builder
	 */
	public ScannerModuleTestBuilder withSchemaName(String schemaName) {
		this.schemaName = schemaName;
		return this;
	}

	public String getMigration() {
		return migration;
	}

	/**
	 * the name of the migrations location
	 *
	 * @param migration the migrations location
	 * @return this builder
	 */
	public ScannerModuleTestBuilder withMigration(String migration) {
		this.migration = migration;
		return this;
	}

	public Class<? extends RuleDto> getSupportedRuleClass() {
		return supportedRuleClass;
	}

	/**
	 * The concrete extension to the RuleDto class that this module uses.
	 *
	 * @param supportedRuleClass the class of Rules this module uses
	 * @return this builder
	 */
	public ScannerModuleTestBuilder withSupportedRuleClass(
			Class<? extends RuleDto> supportedRuleClass) {
		this.supportedRuleClass = supportedRuleClass;
		return this;
	}

	public Supplier<? extends RuleDto> getRuleSupplier() {
		return ruleSupplier;
	}

	/**
	 * A supplier that, when called creates a complete rule for this scanner module. May contain the
	 * same data, but must be unique objects (e.g. construct a new object on each call)
	 *
	 * @param ruleSupplier the Supplier that generates a rule for this module
	 * @return this builder
	 */
	public ScannerModuleTestBuilder withRuleSupplier(
			Supplier<? extends RuleDto> ruleSupplier) {
		this.ruleSupplier = ruleSupplier;
		return this;
	}

	public Set<ScannerModuleTestOption> getIgnoredOptions() {
		return ignoredOptions;
	}

	/**
	 * Adds a {@link ScannerModuleTestOption} to the list of ignored test options. During testing,
	 * these options are used to determine if certain tests should be skipped.
	 *
	 * @param testOption the test option to ignore during testing
	 * @return this builder
	 */
	public ScannerModuleTestBuilder andIgnoreTestOption(ScannerModuleTestOption testOption) {
		ignoredOptions.add(testOption);
		return this;
	}

	public TestScanConfiguration getTestScanConfiguration() {
		return testScanConfig;
	}

	/**
	 * Add a {@link TestScanConfiguration} to the builder so that the module can test a full scan of
	 * a given file and test the report output
	 * 
	 * @param testConfig the Test Scan Config
	 * @return this builder
	 */
	public ScannerModuleTestBuilder withTestScanConfigurationBuilder(
			TestScanConfiguration testConfig) {
		testScanConfig = testConfig;
		return this;
	}


	/**
	 * This Scan Config allows a tester to define a scanning configuration that will exercise the
	 * scanner on a given resource file using a defined ruleset and provide the ability to check the
	 * result against a number of Assertions
	 * 
	 * @author csmith
	 *
	 */
	public static class TestScanConfiguration {
		private String resourceFile;
		private RulesetDto ruleset;
		private Consumer<CodeScanReport> clause;

		public String getResourceFile() {
			return this.resourceFile;
		}

		/**
		 * Add a Resource file from /src/test/resources to this scan configuration. Note that this
		 * must be a simple file, not a file that needs unzipping or other transformation. This
		 * resource must also start with a '/' and be housed in the module's src/test/resources
		 * folder
		 * 
		 * @param resource the resource file to use
		 * @return this builder
		 */
		public TestScanConfiguration withTargetResourceFile(String resource) {
			resourceFile = resource;
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
		public TestScanConfiguration withRuleset(RulesetDto ruleset) {
			this.ruleset = ruleset;
			return this;
		}

		public Consumer<CodeScanReport> getAssertClause() {
			return this.clause;
		}

		/**
		 * Provide a Consumer that will Assert the accuracy of the resulting {@linkplain CodeScanReport}
		 * from the scanner.
		 * 
		 * @param clause the consumer clause that Asserts the correctness of the report
		 * @return this builder
		 */
		public TestScanConfiguration withAssertClause(Consumer<CodeScanReport> clause) {
			this.clause = clause;
			return this;
		}
	}
}
