package com.tracelink.appsec.module.advisory;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import com.tracelink.appsec.module.advisory.designer.AdvisoryRuleDesigner;
import com.tracelink.appsec.module.advisory.editor.AdvisoryRuleEditor;
import com.tracelink.appsec.module.advisory.scanner.AdvisoryScanner;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.module.AbstractImageScanModule;
import com.tracelink.appsec.watchtower.core.module.WatchtowerModule;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.scanner.IImageScanner;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * This module is used to scan Images to identify if any are NOT allowed in a security report
 * 
 * @author csmith
 *
 */
@WatchtowerModule
public class AdvisoryModule extends AbstractImageScanModule {
	public static final String ADVISORY_MODULE_NAME = "Advisory";
	public static final String ADVISORY_RULE_EDITOR_PRIVILEGE_NAME = "Advisory Rule Editor";
	public static final String ADVISORY_RULE_DESIGNER_PRIVILEGE_NAME = "Advisory Rule Designer";
	private final AdvisoryRuleDesigner designer;

	public AdvisoryModule(@Autowired AdvisoryRuleDesigner designer) {
		this.designer = designer;
	}

	@Override
	public IImageScanner getScanner() {
		return new AdvisoryScanner();
	}

	@Override
	public IRuleDesigner getRuleDesigner() {
		return designer;
	}

	@Override
	public IRuleEditor getRuleEditor() {
		return new AdvisoryRuleEditor();
	}

	@Override
	public List<RulesetDto> getProvidedRulesets() {
		return null;
	}

	@Override
	public String getName() {
		return ADVISORY_MODULE_NAME;
	}

	@Override
	public String getSchemaHistoryTable() {
		return "advisory_schema_history";
	}

	@Override
	public String getMigrationsLocation() {
		return "db/advisory";
	}

	@Override
	public List<PrivilegeEntity> getModulePrivileges() {
		return Arrays.asList(new PrivilegeEntity().setName(ADVISORY_RULE_EDITOR_PRIVILEGE_NAME)
				.setCategory("Rule Editor").setDescription(
						"User may edit Advisory rules in the Rule Editor."),
				new PrivilegeEntity().setName(ADVISORY_RULE_DESIGNER_PRIVILEGE_NAME)
						.setCategory("Rule Designer").setDescription(
								"User may create and test Advisory rules in the Rule Designer."));
	}

}
