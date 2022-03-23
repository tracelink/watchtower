package com.tracelink.appsec.module.cve;

import java.util.List;

import com.tracelink.appsec.module.cve.scanner.CveScanner;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.module.AbstractModule;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

public class CveModule extends AbstractModule {
	public static final String MODULE_NAME = "CVE Checker";

	@Override
	public String getName() {
		return MODULE_NAME;
	}

	@Override
	public String getSchemaHistoryTable() {
		return "cve_schema_history";
	}

	@Override
	public String getMigrationsLocation() {
		return "db/cve";
	}

	@Override
	public CveScanner getScanner() {
		return new CveScanner();
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
