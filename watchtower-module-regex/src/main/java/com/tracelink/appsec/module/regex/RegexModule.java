package com.tracelink.appsec.module.regex;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import com.tracelink.appsec.module.regex.designer.RegexRuleDesigner;
import com.tracelink.appsec.module.regex.ruleeditor.RegexRuleEditor;
import com.tracelink.appsec.module.regex.scanner.RegexScanner;
import com.tracelink.appsec.module.regex.service.RegexRuleService;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.module.AbstractCodeScanModule;
import com.tracelink.appsec.watchtower.core.module.WatchtowerModule;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Module to hold implementations for Regex rules, scanner, designer, and XML model.
 *
 * @author mcool, csmith
 */
@WatchtowerModule
public class RegexModule extends AbstractCodeScanModule {
	public static final String REGEX_MODULE_NAME = "Regex";
	public static final String REGEX_RULE_EDIT_PRIVILEGE_NAME = "Regex Rule Editor";
	public static final String REGEX_RULE_DESIGNER_PRIVILEGE_NAME = "Regex Rule Designer";
	private RegexRuleDesigner regexRuleDesigner;
	private RegexRuleService ruleService;

	public RegexModule(@Autowired RegexRuleDesigner regexRuleDesigner,
			@Autowired RegexRuleService ruleService) {
		this.regexRuleDesigner = regexRuleDesigner;
		this.ruleService = ruleService;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return REGEX_MODULE_NAME;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getSchemaHistoryTable() {
		return "regex_schema_history";
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getMigrationsLocation() {
		return "db/regex";
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ICodeScanner getScanner() {
		return new RegexScanner();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IRuleDesigner getRuleDesigner() {
		return regexRuleDesigner;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public IRuleEditor getRuleEditor() {
		return new RegexRuleEditor();
	}

	@Override
	public List<PrivilegeEntity> getModulePrivileges() {
		return Arrays.asList(new PrivilegeEntity().setName(REGEX_RULE_EDIT_PRIVILEGE_NAME)
				.setCategory("Rule Editor").setDescription(
						"User may edit Regex rules in the Rule Editor."),
				new PrivilegeEntity().setName(REGEX_RULE_DESIGNER_PRIVILEGE_NAME)
						.setCategory("Rule Designer").setDescription(
								"User may create and test Regex rules in the Rule Designer."));
	}

	@Override
	public List<RulesetDto> getProvidedRulesets() {
		return ruleService.getProvidedRulesets();
	}
}
