package com.tracelink.appsec.module.regex.controller;

import static com.tracelink.appsec.watchtower.core.rule.RuleEditController.RULE_EDIT_REDIRECT;

import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.module.regex.RegexModule;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.module.regex.model.RegexProvidedRuleDto;
import com.tracelink.appsec.module.regex.service.RegexRuleService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditorException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

/**
 * Controller to handle editing a Regex rule.
 *
 * @author mcool
 */
@Controller
@PreAuthorize("hasAuthority('" + RegexModule.REGEX_RULE_EDIT_PRIVILEGE_NAME + "')")
public class RegexRuleEditController {
	private RegexRuleService regexRuleService;
	private RuleService ruleService;

	public RegexRuleEditController(@Autowired RegexRuleService regexRuleService,
			@Autowired RuleService ruleService) {
		this.regexRuleService = regexRuleService;
		this.ruleService = ruleService;
	}

	@PostMapping("/rule/edit/regex/edit/custom")
	public String editRule(@Valid RegexCustomRuleDto dto, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		return editRuleInner(dto, bindingResult, redirectAttributes);
	}

	@PostMapping("/rule/edit/regex/edit/provided")
	public String editRule(@Valid RegexProvidedRuleDto dto, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		return editRuleInner(dto, bindingResult, redirectAttributes);
	}

	private String editRuleInner(RuleDto dto, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		// Validate and Edit rule
		try {
			validateRule(dto.getId(), dto.getName(), bindingResult);
			regexRuleService.editRule(dto);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully edited rule.");
		} catch (RuleNotFoundException | RuleEditorException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit rule. " + e.getMessage());
		}
		return RULE_EDIT_REDIRECT + "/regex/" + dto.getId();
	}

	private void validateRule(Long id, String name, BindingResult bindingResult)
			throws RuleEditorException {
		// Validate fields
		if (bindingResult.hasErrors()) {
			String error = bindingResult.getFieldErrors().stream()
					.map(FieldError::getDefaultMessage).collect(Collectors.joining(", "));
			throw new RuleEditorException(error);
		}
		// Prevent name collisions
		if (ruleService.createsNameCollision(id, name)) {
			throw new RuleEditorException(
					"A rule with the name \"" + name + "\" already exists.");
		}
	}
}
