package com.tracelink.appsec.module.eslint.controller;

import java.util.List;
import java.util.stream.Collectors;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.module.eslint.designer.EsLintRuleDesigner;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.service.EsLintRuleService;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;

/**
 * Controller to handle requests for designing an ESLint custom or core rule.
 *
 * @author mcool
 */
@Controller
@RequestMapping("/designer/eslint")
@PreAuthorize("hasAuthority('" + EsLintModule.ESLINT_RULE_DESIGNER_PRIVILEGE_NAME + "')")
public class EsLintRuleDesignerController {

	private final EsLintRuleDesigner ruleDesigner;
	private final RuleDesignerService ruleDesignerService;
	private final EsLintRuleService ruleService;

	public EsLintRuleDesignerController(@Autowired EsLintRuleDesigner ruleDesigner,
			@Autowired RuleDesignerService ruleDesignerService,
			@Autowired EsLintRuleService ruleService) {
		this.ruleDesigner = ruleDesigner;
		this.ruleDesignerService = ruleDesignerService;
		this.ruleService = ruleService;
	}

	@PostMapping("query")
	public RuleDesignerModelAndView query(@RequestParam String sourceCode,
			EsLintCustomRuleDto rule, Authentication auth) {
		RuleDesignerModelAndView mav =
				ruleDesigner.query(sourceCode, rule.getCreateFunction(), rule.getMessages());
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
		return mav;
	}

	@PostMapping("save")
	public RuleDesignerModelAndView save(@RequestParam String sourceCode,
			@Valid EsLintCustomRuleDto rule, BindingResult bindingResult,
			RedirectAttributes redirectAttributes, Authentication auth) {
		// Set principal as author
		rule.setAuthor(auth.getName());
		// Validate ruleset
		if (bindingResult.hasErrors()) {
			List<FieldError> error = bindingResult.getFieldErrors();
			RuleDesignerModelAndView mav = ruleDesigner.getRuleDesignerModelAndView();
			mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
			mav.addErrorMessage("Failed to validate rule. " + error.stream()
					.map(FieldError::getDefaultMessage).collect(Collectors.joining(",")));
			return mav;
		}
		// Run query to get ModelAndView
		RuleDesignerModelAndView mav = ruleDesigner.query(sourceCode, rule);
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));

		// Try to save rule and perform any additional validation
		try {
			ruleService.saveRule(rule);
			mav.addSuccessMessage("Successfully saved rule: " + rule.getName());
		} catch (RuleDesignerException e) {
			mav.addErrorMessage("Failed to save rule. " + e.getMessage());
		}
		return mav;
	}
}
