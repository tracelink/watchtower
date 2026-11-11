package com.tracelink.appsec.module.checkov;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import com.tracelink.appsec.module.checkov.editor.CheckovRuleEditor;
import com.tracelink.appsec.module.checkov.engine.CheckovEngine;
import com.tracelink.appsec.module.checkov.scanner.CheckovScanner;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.module.AbstractCodeScanModule;
import com.tracelink.appsec.watchtower.core.module.WatchtowerModule;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Checkov is a scanner for Intrastructure As Code (IAC) maintained by Bridgecrew at
 * <a href="https://www.checkov.io/">https://www.checkov.io</a> <br>
 * Checkov integrates with Watchtower by using a pip-packaged python module system. The scanner
 * requires Python 3.
 * 
 * @author csmith
 *
 */
@WatchtowerModule
public class CheckovModule extends AbstractCodeScanModule {

	public static final String MODULE_NAME = "Checkov";
	private final CheckovEngine engine;

	public static final String CHECKOV_RULE_PRIVILEGE_NAME = "Checkov Rule Editor";

	public CheckovModule() {
		this(new CheckovEngine());
	}

	public CheckovModule(CheckovEngine engine) {
		this.engine = engine;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return MODULE_NAME;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getSchemaHistoryTable() {
		return "checkov_schema_history";
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getMigrationsLocation() {
		return "db/checkov";
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ICodeScanner getScanner() {
		return new CheckovScanner(engine);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IRuleDesigner getRuleDesigner() {
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IRuleEditor getRuleEditor() {
		return new CheckovRuleEditor();
	}

	@Override
	public List<PrivilegeEntity> getModulePrivileges() {
		return Arrays.asList(new PrivilegeEntity().setName(CHECKOV_RULE_PRIVILEGE_NAME)
				.setCategory("Rule Editing").setDescription(
						"Users may Edit Checkov rules in the Rule Editor. Caution! This privilege allows Code Execution on the Watchtower machine as Checkov runs directly as a python task"));
	}

	@Override
	public List<RulesetDto> getProvidedRulesets() {
		return engine.getCoreRulesets().values().stream()
				.collect(Collectors.toList());
	}
}
