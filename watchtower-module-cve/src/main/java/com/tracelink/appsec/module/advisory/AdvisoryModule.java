package com.tracelink.appsec.module.advisory;

import java.util.List;

import com.tracelink.appsec.module.advisory.scanner.AdvisoryScanner;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.module.AbstractModule;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

public class AdvisoryModule extends AbstractModule {
	public static final String MODULE_NAME = "Image Advisory Checker";

	@Override
	public String getName() {
		return MODULE_NAME;
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
	public AdvisoryScanner getScanner() {
		return new AdvisoryScanner();
	}

	@Override
	public IRuleDesigner getRuleDesigner() {
		return null;
	}

	@Override
	public IRuleEditor getRuleEditor() {
		return null;
	}

	@Override
	public List<PrivilegeEntity> getModulePrivileges() {
		return null;
	}

	@Override
	public List<RulesetDto> getProvidedRulesets() {
		return null;
	}

}
