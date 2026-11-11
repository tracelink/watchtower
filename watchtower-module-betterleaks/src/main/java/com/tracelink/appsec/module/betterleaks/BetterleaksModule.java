package com.tracelink.appsec.module.betterleaks;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;

import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistProvider;
import com.tracelink.appsec.module.betterleaks.allowlist.BetterleaksAllowlistService;
import com.tracelink.appsec.module.betterleaks.designer.BetterleaksRuleDesigner;
import com.tracelink.appsec.module.betterleaks.service.BetterleaksRuleService;
import com.tracelink.appsec.module.betterleaks.editor.BetterleaksRuleEditor;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksEngine;
import com.tracelink.appsec.module.betterleaks.rules.BetterleaksProvidedRules;
import com.tracelink.appsec.module.betterleaks.scanner.BetterleaksScanner;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.module.AbstractCodeScanModule;
import com.tracelink.appsec.watchtower.core.module.WatchtowerModule;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.sidebar.SidebarLink;
import com.tracelink.appsec.watchtower.core.sidebar.SidebarService;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;

/**
 * Secrets detection with <a href="https://github.com/betterleaks/betterleaks">Betterleaks</a>
 * (MIT), run as an external binary. Like every module it runs only when a repository's ruleset
 * contains its rules, and blocking follows the rule priority against the ruleset's blocking level.
 * <p>
 * The binary is found through {@link BetterleaksEngine#BINARY_PATH_ENV}, else {@code betterleaks}
 * on the PATH, and must be version {@link #BETTERLEAKS_VERSION}.
 *
 * @author Watchtower
 */
@WatchtowerModule
public class BetterleaksModule extends AbstractCodeScanModule {

	public static final String MODULE_NAME = "Betterleaks";

	/** The binary version the provided rules and engine flags were verified against. */
	public static final String BETTERLEAKS_VERSION = "1.8.1";

	public static final String RULE_EDITOR_PRIVILEGE_NAME = "Betterleaks Rule Editor";

	public static final String ALLOWLIST_PRIVILEGE_NAME = "Betterleaks Allowlist Modify";

	public static final String RULE_DESIGNER_PRIVILEGE_NAME = "Betterleaks Rule Designer";

	public static final String VERIFY_PRIVILEGE_NAME = "Betterleaks Verify Live";

	static final String ALLOWLIST_URL = "/betterleaks/allowlist";

	private final BetterleaksEngine engine;

	private BetterleaksAllowlistProvider allowlistProvider = BetterleaksAllowlistProvider.NONE;

	private MeterRegistry meterRegistry;

	private SidebarService sidebarService;

	private BetterleaksRuleDesigner ruleDesigner;

	private BetterleaksRuleService ruleService;

	@Autowired(required = false)
	void setRuleDesigner(BetterleaksRuleDesigner ruleDesigner) {
		this.ruleDesigner = ruleDesigner;
	}

	@Autowired(required = false)
	void setRuleService(BetterleaksRuleService ruleService) {
		this.ruleService = ruleService;
	}

	public BetterleaksModule() {
		this(new BetterleaksEngine());
	}

	public BetterleaksModule(BetterleaksEngine engine) {
		this.engine = engine;
	}

	@Autowired(required = false)
	void setAllowlistService(BetterleaksAllowlistService allowlistService) {
		this.allowlistProvider = allowlistService;
	}

	@Autowired(required = false)
	void setMeterRegistry(MeterRegistry meterRegistry) {
		this.meterRegistry = meterRegistry;
	}

	@Autowired(required = false)
	void setSidebarService(SidebarService sidebarService) {
		this.sidebarService = sidebarService;
	}

	/**
	 * Lists the allowlist page under Configuration. Runs after the module is built.
	 */
	@PostConstruct
	void registerSidebarLink() {
		if (sidebarService != null) {
			sidebarService.addLink("Configuration", new SidebarLink()
					.setDisplayName("Secrets Allowlist")
					.setMaterialIcon("rule")
					.setUrl(ALLOWLIST_URL)
					.setAuthorizationExpression(
							"hasAuthority('" + ALLOWLIST_PRIVILEGE_NAME + "')"));
		}
	}

	@Override
	public String getName() {
		return MODULE_NAME;
	}

	@Override
	public String getSchemaHistoryTable() {
		return "betterleaks_schema_history";
	}

	@Override
	public String getMigrationsLocation() {
		return "db/betterleaks";
	}

	@Override
	public ICodeScanner getScanner() {
		return new BetterleaksScanner(engine, allowlistProvider, meterRegistry);
	}

	@Override
	public IRuleDesigner getRuleDesigner() {
		return ruleDesigner;
	}

	@Override
	public IRuleEditor getRuleEditor() {
		return ruleService == null ? new BetterleaksRuleEditor()
				: new BetterleaksRuleEditor(ruleService::getVersions);
	}

	@Override
	public List<PrivilegeEntity> getModulePrivileges() {
		return List.of(
				new PrivilegeEntity().setName(RULE_EDITOR_PRIVILEGE_NAME)
						.setCategory("Rule Editing")
						.setDescription("Users may change the priority of Betterleaks rules in the"
								+ " Rule Editor, which decides whether a detected secret blocks a"
								+ " pull request."),
				new PrivilegeEntity().setName(RULE_DESIGNER_PRIVILEGE_NAME)
						.setCategory("Rule Editing")
						.setDescription("Users may write, test and edit custom Betterleaks"
								+ " rules, which decide what counts as a secret."),
				new PrivilegeEntity().setName(ALLOWLIST_PRIVILEGE_NAME)
						.setCategory("Configuration")
						.setDescription("Users may add and remove Betterleaks allowlist entries,"
								+ " which silence secrets findings. Grant to AppSec only."),
				new PrivilegeEntity().setName(VERIFY_PRIVILEGE_NAME)
						.setCategory("Scanning")
						.setDescription("Users may ask a secret's provider whether a secret"
								+ " found in a pull request still works. This sends the secret to"
								+ " its provider. Grant to AppSec only."));
	}

	@Override
	public List<RulesetDto> getProvidedRulesets() {
		return List.of(BetterleaksProvidedRules.load().toDefaultRuleset());
	}
}
