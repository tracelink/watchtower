package com.tracelink.appsec.module.betterleaks.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.betterleaks.designer.BetterleaksCustomRuleForm;
import com.tracelink.appsec.module.betterleaks.designer.BetterleaksRuleDesigner;
import com.tracelink.appsec.module.betterleaks.service.BetterleaksRuleService;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;

/**
 * Tests and saves custom Betterleaks rules from the designer.
 *
 * @author Watchtower
 */
@Controller
@PreAuthorize("hasAuthority('" + BetterleaksModule.RULE_DESIGNER_PRIVILEGE_NAME + "')")
public class BetterleaksDesignerController {

	private final BetterleaksRuleDesigner designer;

	private final BetterleaksRuleService ruleService;

	private final RuleDesignerService ruleDesignerService;

	public BetterleaksDesignerController(@Autowired BetterleaksRuleDesigner designer,
			@Autowired BetterleaksRuleService ruleService,
			@Autowired RuleDesignerService ruleDesignerService) {
		this.designer = designer;
		this.ruleService = ruleService;
		this.ruleDesignerService = ruleDesignerService;
	}

	/**
	 * The designer form's single target: its Test and Save buttons submit {@code action}.
	 */
	@PostMapping("/designer/betterleaks")
	public RuleDesignerModelAndView submit(@ModelAttribute BetterleaksCustomRuleForm form,
			@RequestParam(defaultValue = "test") String action, Authentication auth) {
		return "save".equals(action) ? saveRule(form, auth) : testRule(form, auth);
	}

	@PostMapping("/designer/betterleaks/test")
	public RuleDesignerModelAndView testRule(@ModelAttribute BetterleaksCustomRuleForm form,
			Authentication auth) {
		RuleDesignerModelAndView mav = designer.test(form);
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
		return mav;
	}

	@PostMapping("/designer/betterleaks/save")
	public RuleDesignerModelAndView saveRule(@ModelAttribute BetterleaksCustomRuleForm form,
			Authentication auth) {
		RuleDesignerModelAndView mav = designer.view(form);
		try {
			ruleService.saveNewCustomRule(form.toRule(), auth.getName());
			mav.addSuccessMessage("Saved rule " + form.toRule().getName()
					+ ". Add it to a ruleset to start scanning with it.");
		} catch (IllegalArgumentException e) {
			mav.addErrorMessage("Cannot save rule. " + e.getMessage());
		}
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
		return mav;
	}
}
