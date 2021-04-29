package com.tracelink.appsec.watchtower.core.rule;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;

/**
 * Controller for operations to edit or delete Rules. Creates the shell and a listing of rules per
 * module, but defers to the module to display the user experience needed to edit a particular rule
 *
 * @author mcool
 */
@Controller
@RequestMapping("/rule/edit")
@PreAuthorize("hasAuthority('" + CorePrivilege.RULE_MODIFY_NAME + "')")
public class RuleEditController {
	public static final String RULE_EDIT_REDIRECT = "redirect:/rule/edit";
	private RuleEditorService ruleEditorService;
	private RuleService ruleService;
	private RulesetService rulesetService;

	public RuleEditController(@Autowired RuleEditorService ruleEditorService,
			@Autowired RuleService ruleService,
			@Autowired RulesetService rulesetService) {
		this.ruleEditorService = ruleEditorService;
		this.ruleService = ruleService;
		this.rulesetService = rulesetService;
	}

	@GetMapping("")
	public String getRuleEdit(RedirectAttributes redirectAttributes) {
		String defaultModule = ruleEditorService.getDefaultRuleEditModule();
		if (defaultModule == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"There are no modules configured for Watchtower");
			return "redirect:/";
		}
		return RULE_EDIT_REDIRECT + "/" + defaultModule.toLowerCase();
	}

	@GetMapping("/{module}")
	public WatchtowerModelAndView getRuleEditByModule(@PathVariable String module,
			RedirectAttributes redirectAttributes) {
		try {
			return ruleEditorService.getRuleEditModelAndView(module, null);
		} catch (RuleNotFoundException | ModuleNotFoundException e) {
			// RuleNotFound won't be called, so merging their responses
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
			return errorMAV(getRuleEdit(redirectAttributes));
		}
	}

	@GetMapping("/{module}/{ruleId}")
	public WatchtowerModelAndView getRuleEditByRule(@PathVariable String module,
			@PathVariable long ruleId, RedirectAttributes redirectAttributes) {
		try {
			return ruleEditorService.getRuleEditModelAndView(module, ruleId);
		} catch (ModuleNotFoundException e) {
			// If the module is wrong, go find the default
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
			return errorMAV(getRuleEdit(redirectAttributes));
		} catch (RuleNotFoundException e) {
			// If the rule is wrong stick with this module
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					e.getMessage());
			return errorMAV(RULE_EDIT_REDIRECT + "/" + module);
		}
	}

	private WatchtowerModelAndView errorMAV(String view) {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("");
		mav.setViewName(view);
		return mav;
	}

	@PostMapping("/{module}/delete")
	public String deleteRule(@PathVariable String module, @RequestParam long ruleId,
			RedirectAttributes redirectAttributes) {
		try {
			rulesetService.removeRuleFromAllRulesets(ruleId);
			ruleService.deleteRule(ruleId);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully deleted rule.");
		} catch (RuleNotFoundException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot delete rule. " + e.getMessage());
		}
		return RULE_EDIT_REDIRECT + "/" + module;
	}

}
