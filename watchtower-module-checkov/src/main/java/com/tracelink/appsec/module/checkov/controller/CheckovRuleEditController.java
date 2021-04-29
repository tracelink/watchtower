package com.tracelink.appsec.module.checkov.controller;

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

import com.tracelink.appsec.module.checkov.CheckovModule;
import com.tracelink.appsec.module.checkov.model.CheckovRuleDto;
import com.tracelink.appsec.module.checkov.service.CheckovRuleService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditorException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

/**
 * Controller to handle editing Checkov Rules
 * 
 * @author csmith
 *
 */
@Controller
@PreAuthorize("hasAuthority('" + CheckovModule.CHECKOV_RULE_PRIVILEGE_NAME + "')")
public class CheckovRuleEditController {
	private final CheckovRuleService checkovRuleService;
	private final RuleService ruleService;

	public CheckovRuleEditController(@Autowired CheckovRuleService checkovRuleService,
			@Autowired RuleService ruleService) {
		this.checkovRuleService = checkovRuleService;
		this.ruleService = ruleService;
	}

	@PostMapping("/rule/edit/checkov")
	public String editRule(@Valid CheckovRuleDto dto, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		// Validate and Edit rule
		try {
			validateRule(dto.getId(), dto.getName(), bindingResult);
			checkovRuleService.editRule(dto);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully edited rule.");
		} catch (RuleNotFoundException | RuleEditorException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit rule. " + e.getMessage());
		}
		return RULE_EDIT_REDIRECT + "/checkov/" + dto.getId();
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
