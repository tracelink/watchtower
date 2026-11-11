package com.tracelink.appsec.module.betterleaks.controller;

import static com.tracelink.appsec.watchtower.core.rule.RuleEditController.RULE_EDIT_REDIRECT;

import java.security.Principal;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.betterleaks.designer.BetterleaksCustomRuleForm;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.module.betterleaks.service.BetterleaksRuleService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

import jakarta.validation.Valid;

/**
 * Handles edits to Betterleaks rules from the rule editor.
 *
 * @author Watchtower
 */
@Controller
@PreAuthorize("hasAuthority('" + BetterleaksModule.RULE_EDITOR_PRIVILEGE_NAME + "')")
public class BetterleaksRuleEditController {

	private final BetterleaksRuleService betterleaksRuleService;

	public BetterleaksRuleEditController(
			@Autowired BetterleaksRuleService betterleaksRuleService) {
		this.betterleaksRuleService = betterleaksRuleService;
	}

	/**
	 * Saves a provided rule's priority.
	 *
	 * @param dto                the submitted rule
	 * @param bindingResult      validation of the submitted rule
	 * @param redirectAttributes carries the outcome notification to the redirected page
	 * @return a redirect back to the rule's edit page
	 */
	@PostMapping("/rule/edit/betterleaks")
	public String editRule(@Valid BetterleaksProvidedRuleDto dto, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		if (bindingResult.hasErrors()) {
			String errors = bindingResult.getFieldErrors().stream()
					.map(FieldError::getDefaultMessage).collect(Collectors.joining(", "));
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit rule. " + errors);
			return RULE_EDIT_REDIRECT + "/betterleaks/" + dto.getId();
		}
		try {
			betterleaksRuleService.editProvidedRule(dto);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully edited rule.");
		} catch (RuleNotFoundException | IllegalArgumentException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit rule. " + e.getMessage());
		}
		return RULE_EDIT_REDIRECT + "/betterleaks/" + dto.getId();
	}

	/**
	 * Saves a new version of a custom rule. Changing what a secrets rule detects needs the
	 * designer privilege as well as the editor one.
	 *
	 * @param form               the submitted rule
	 * @param principal          who is editing it
	 * @param redirectAttributes carries the outcome notification to the redirected page
	 * @return a redirect back to the rule's edit page
	 */
	@PostMapping("/rule/edit/betterleaks/custom")
	@PreAuthorize("hasAuthority('" + BetterleaksModule.RULE_EDITOR_PRIVILEGE_NAME
			+ "') and hasAuthority('" + BetterleaksModule.RULE_DESIGNER_PRIVILEGE_NAME + "')")
	public String editCustomRule(@ModelAttribute BetterleaksCustomRuleForm form,
			Principal principal, RedirectAttributes redirectAttributes) {
		try {
			betterleaksRuleService.editCustomRule(form.toRule(), principal.getName());
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Saved a new version of the rule.");
		} catch (IllegalArgumentException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit rule. " + e.getMessage());
		}
		return RULE_EDIT_REDIRECT + "/betterleaks/" + form.getId();
	}
}
