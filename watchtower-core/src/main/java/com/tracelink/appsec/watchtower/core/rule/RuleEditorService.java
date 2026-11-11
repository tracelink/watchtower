package com.tracelink.appsec.watchtower.core.rule;

import java.util.List;
import java.util.Set;
import java.util.TreeMap;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditModelAndView;

/**
 * Provides business logic to register module rule editors and get their
 * {@link RuleEditModelAndView}
 *
 * @author mcool, csmith
 */
@Service
public class RuleEditorService {
	private RuleService ruleService;

	/**
	 * Map from module name to the path to the edit rule HTML file
	 */
	@org.springframework.beans.factory.annotation.Autowired(required=false)
	private com.tracelink.appsec.watchtower.core.module.ModuleControlService moduleControls;

	private TreeMap<String, IRuleEditor> moduleMapping =
			new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

	/** Names and checks the CWEs shown on the rule page; absent in tests that do not need it. */
	private com.tracelink.appsec.watchtower.core.cwe.CweCatalogService cweCatalog;

	@Autowired(required = false)
	public void setCweCatalog(com.tracelink.appsec.watchtower.core.cwe.CweCatalogService cweCatalog) {
		this.cweCatalog = cweCatalog;
	}

	public RuleEditorService(@Autowired RuleService ruleService) {
		this.ruleService = ruleService;
	}

	/**
	 * Registers a rule type with this service, along with the rule editor implementation that
	 * supplies a {@link RuleEditModelAndView}
	 *
	 * @param module     module name
	 * @param ruleEditor the rule editor implementation
	 * @throws IllegalArgumentException if the module name or rule editor is blank/null
	 * @throws ModuleException          if the module name already exists
	 */
	public void registerRuleEditor(String module,
			IRuleEditor ruleEditor)
			throws IllegalArgumentException, ModuleException {
		if (StringUtils.isBlank(module) || ruleEditor == null) {
			throw new IllegalArgumentException(
					"Module and rule editor cannot be blank or null.");
		}
		if (moduleMapping.containsKey(module)) {
			throw new ModuleException(
					"An rule editor for the given module already exists: " + module);
		}
		moduleMapping.put(module, ruleEditor);
	}

	/**
	 * Get the set of module names configured in this service
	 * 
	 * @return the set of module names configured in this service
	 */
	public Set<String> getKnownModules() {
		return moduleMapping.keySet();
	}

	/**
	 * Get the default module name, or null if none are configured
	 * 
	 * @return the default module name, or null if none are configured
	 */
	public String getDefaultRuleEditModule() {
		return moduleMapping.isEmpty() ? null : moduleMapping.firstKey();
	}


	/**
	 * Get the RuleEdit MAV for this module and ruleID. This will also ensure that the surrounding
	 * container view of the rule editor has all rules for this module.
	 * 
	 * @param module the module name
	 * @param ruleId the rule id to get
	 * @return a {@link RuleEditModelAndView} for this module and rule
	 * @throws ModuleNotFoundException if the Module is unknown
	 * @throws RuleNotFoundException   if the rule is unknown for this module
	 */
	public RuleEditModelAndView getRuleEditModelAndView(String module, Long ruleId)
			throws ModuleNotFoundException, RuleNotFoundException {
		if (!getKnownModules().contains(module)) {
			throw new ModuleNotFoundException("Unknown module: " + module);
		}

		List<RuleDto> rules = ruleService.getRulesForModule(module);
		RuleDto rule;
		if (ruleId == null) {
			// Open on the first rule (a custom one when the module has any), so the editor is never
			// an empty "Select a rule" box (UAT walkthrough, 2026-10-16; #27).
			rule = rules.stream().filter(RuleDto::isCustom).findFirst()
					.orElse(rules.isEmpty() ? null : rules.get(0));
		} else {
			rule = rules.stream()
					.filter(r -> r.getId().equals(ruleId))
					.findAny()
					.orElseThrow(() -> new RuleNotFoundException("Unknown Rule and module pair"));
		}
		// No rule at all: a blank page; otherwise the scanner module draws the rule.
		RuleEditModelAndView mv = rule == null ? new RuleEditModelAndView("")
				: this.moduleMapping.get(module).getDefaultRuleEditModelAndView(rule);

		long customCount = rules.stream().filter(RuleDto::isCustom).count();
		mv.addObject("modules", getKnownModules());
		mv.addObject("rules", rules);
		mv.addObject("customCount", customCount);
		mv.addObject("providedCount", rules.size() - customCount);
		mv.addObject("activeModule", module);
		mv.addObject("moduleDisabled", moduleControls != null && !moduleControls.enabled(module));
		mv.addObject("activeRule", rule);
		// Ready-made chips, so the page never reaches into the CWE catalog itself.
		mv.addObject("cweChips", rule == null || cweCatalog == null ? List.of()
				: cweCatalog.chipsFor(rule.getStewardship().getCwe(), rule.getStewardship().getSecondaryCwes()));

		return mv;
	}
}
