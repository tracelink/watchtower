package com.tracelink.appsec.module.pmd;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import com.tracelink.appsec.module.pmd.designer.PMDRuleDesigner;
import com.tracelink.appsec.module.pmd.interpreter.PMDRulesetInterpreter;
import com.tracelink.appsec.module.pmd.ruleeditor.PMDRuleEditor;
import com.tracelink.appsec.module.pmd.scanner.PMDScanner;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.module.AbstractModule;
import com.tracelink.appsec.watchtower.core.module.WatchtowerModule;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.interpreter.IRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;

/**
 * Module to hold implementations for PMD rules, scanner, designer, and XML model.
 *
 * @author mcool, csmith
 */
@WatchtowerModule
public class PMDModule extends AbstractModule {
	public static final String PMD_MODULE_NAME = "PMD";
	public static final String PMD_RULE_EDIT_PRIVILEGE_NAME = "PMD Rule Editor";
	public static final String PMD_RULE_DESIGNER_PRIVILEGE_NAME = "PMD Rule Designer";

	private PMDRuleDesigner pmdRuleDesigner;

	public PMDModule(@Autowired PMDRuleDesigner ruleDesigner) {
		this.pmdRuleDesigner = ruleDesigner;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return PMD_MODULE_NAME;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getSchemaHistoryTable() {
		return "pmd_schema_history";
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getMigrationsLocation() {
		return "db/pmd";
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IScanner getScanner() {
		return new PMDScanner();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IRuleDesigner getRuleDesigner() {
		return pmdRuleDesigner;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IRuleEditor getRuleEditor() {
		return new PMDRuleEditor();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IRulesetInterpreter getInterpreter() {
		return new PMDRulesetInterpreter();
	}

	@Override
	public List<PrivilegeEntity> getModulePrivileges() {
		return Arrays.asList(new PrivilegeEntity().setName(PMD_RULE_EDIT_PRIVILEGE_NAME)
				.setCategory("Rule Editor").setDescription(
						"User may edit PMD rules in the Rule Editor."),
				new PrivilegeEntity().setName(PMD_RULE_DESIGNER_PRIVILEGE_NAME)
						.setCategory("Rule Designer").setDescription(
								"User may create and test PMD rules in the Rule Designer."));
	}
}
