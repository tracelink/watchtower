package com.tracelink.appsec.module.json;

import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import com.tracelink.appsec.module.json.designer.JsonRuleDesigner;
import com.tracelink.appsec.module.json.interpreter.JsonRulesetInterpreter;
import com.tracelink.appsec.module.json.ruleeditor.JsonRuleEditor;
import com.tracelink.appsec.module.json.scanner.JsonScanner;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.module.AbstractModule;
import com.tracelink.appsec.watchtower.core.module.WatchtowerModule;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.interpreter.IRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * Module to hold implementations for JSON rules, scanner, designer, and XML model.
 *
 * @author csmith
 */
@WatchtowerModule
public class JsonModule extends AbstractModule {
	public static final String SCANNER_NAME = "JSON";
	public static final String JSON_RULE_EDITOR_PRIVILEGE_NAME = "JSON Rule Editor";
	public static final String JSON_RULE_DESIGNER_PRIVILEGE_NAME = "JSON Rule Designer";
	private JsonRuleDesigner ruleDesigner;

	public JsonModule(@Autowired JsonRuleDesigner ruleDesigner) {
		this.ruleDesigner = ruleDesigner;
	}

	@Override
	public String getName() {
		return SCANNER_NAME;
	}

	@Override
	public String getSchemaHistoryTable() {
		return "json_schema_history";
	}

	@Override
	public String getMigrationsLocation() {
		return "db/json";
	}

	@Override
	public IScanner getScanner() {
		return new JsonScanner();
	}

	@Override
	public IRuleDesigner getRuleDesigner() {
		return ruleDesigner;
	}

	@Override
	public IRuleEditor getRuleEditor() {
		return new JsonRuleEditor();
	}

	@Override
	public IRulesetInterpreter getInterpreter() {
		return new JsonRulesetInterpreter();
	}

	@Override
	public List<PrivilegeEntity> getModulePrivileges() {
		return Arrays.asList(new PrivilegeEntity().setName(JSON_RULE_EDITOR_PRIVILEGE_NAME)
				.setCategory("Rule Editor").setDescription(
						"User may edit JSON rules in the Rule Editor."),
				new PrivilegeEntity().setName(JSON_RULE_DESIGNER_PRIVILEGE_NAME)
						.setCategory("Rule Designer").setDescription(
								"User may create and test JSON rules in the Rule Designer."));
	}

	@Override
	public List<RulesetDto> getProvidedRulesets() {
		return null;
	}

}
