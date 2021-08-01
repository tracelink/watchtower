package com.tracelink.appsec.module.pmd.controller;

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

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditorException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

/**
 * Controller to handle editing a PMD rule.
 *
 * @author mcool
 */
@Controller
@PreAuthorize("hasAuthority('" + PMDModule.PMD_RULE_EDIT_PRIVILEGE_NAME + "')")
public class PMDRuleEditController {
	private PMDRuleService pmdRuleService;
	private RuleService ruleService;

	public PMDRuleEditController(@Autowired PMDRuleService pmdRuleService,
			@Autowired RuleService ruleService) {
		this.pmdRuleService = pmdRuleService;
		this.ruleService = ruleService;
	}

	@PostMapping("/rule/edit/pmd/edit")
	public String editRule(@Valid PMDCustomRuleDto dto, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		// Validate and Edit rule
		try {
			validateRule(dto.getId(), dto.getName(), bindingResult);
			pmdRuleService.editRule(dto);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully edited rule.");
		} catch (RuleNotFoundException | RuleEditorException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit rule. " + e.getMessage());
		}
		return RULE_EDIT_REDIRECT + "/pmd/" + dto.getId();
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
