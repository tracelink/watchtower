package com.tracelink.appsec.module.eslint.controller;

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

import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintProvidedRuleDto;
import com.tracelink.appsec.module.eslint.service.EsLintRuleService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditorException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

/**
 * Controller to handle editing an ESLint rule.
 *
 * @author mcool
 */
@Controller
@PreAuthorize("hasAuthority('" + EsLintModule.ESLINT_RULE_EDIT_PRIVILEGE_NAME + "')")
public class EsLintRuleEditController {

	private final EsLintRuleService esLintRuleService;
	private final RuleService ruleService;

	public EsLintRuleEditController(@Autowired EsLintRuleService esLintRuleService,
			@Autowired RuleService ruleService) {
		this.esLintRuleService = esLintRuleService;
		this.ruleService = ruleService;
	}

	@PostMapping("/rule/edit/eslint/custom")
	public String editRule(@Valid EsLintCustomRuleDto dto, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		return editRuleInner(dto, bindingResult, redirectAttributes);
	}

	@PostMapping("/rule/edit/eslint/core")
	public String editRule(@Valid EsLintProvidedRuleDto dto, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		return editRuleInner(dto, bindingResult, redirectAttributes);
	}

	private String editRuleInner(RuleDto dto, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		// Validate and Edit rule
		try {
			validateRule(dto.getId(), dto.getName(), bindingResult);
			esLintRuleService.editRule(dto);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully edited rule.");
		} catch (RuleNotFoundException | RuleEditorException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit rule. " + e.getMessage());
		}
		return RULE_EDIT_REDIRECT + "/eslint/" + dto.getId();
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
