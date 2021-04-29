package com.tracelink.appsec.module.json.controller;

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

import com.tracelink.appsec.module.json.JsonModule;
import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.module.json.service.JsonRuleService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.RuleEditorException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

/**
 * Controller to handle editing a JSON rule.
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + JsonModule.JSON_RULE_EDITOR_PRIVILEGE_NAME + "')")
public class JsonRuleEditController {
	private JsonRuleService jsonRuleService;
	private RuleService ruleService;

	public JsonRuleEditController(@Autowired JsonRuleService jsonRuleService,
			@Autowired RuleService ruleService) {
		this.jsonRuleService = jsonRuleService;
		this.ruleService = ruleService;
	}

	@PostMapping("/rule/edit/json")
	public String editRule(@Valid JsonRuleDto dto, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		// Validate and Edit rule
		try {
			validateRule(dto, bindingResult);
			jsonRuleService.editRule(dto);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully edited rule.");
		} catch (RuleNotFoundException | RuleEditorException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit rule. " + e.getMessage());
		}
		return RULE_EDIT_REDIRECT + "/json/" + dto.getId();
	}

	private void validateRule(JsonRuleDto dto, BindingResult bindingResult)
			throws RuleEditorException {
		// Validate fields
		if (bindingResult.hasErrors()) {
			String error = bindingResult.getFieldErrors().stream()
					.map(FieldError::getDefaultMessage).collect(Collectors.joining(", "));
			throw new RuleEditorException(error);
		}
		try {
			dto.getCompiledQuery();
		} catch (Exception e) {
			throw new RuleEditorException("Could not compile query");
		}
		// Prevent name collisions
		if (ruleService.createsNameCollision(dto.getId(), dto.getName())) {
			throw new RuleEditorException(
					"A rule with the name \"" + dto.getName() + "\" already exists.");
		}
	}
}
