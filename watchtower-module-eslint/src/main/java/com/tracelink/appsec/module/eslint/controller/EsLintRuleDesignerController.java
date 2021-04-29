package com.tracelink.appsec.module.eslint.controller;

import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.module.eslint.designer.EsLintRuleDesigner;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDto;
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
	private final Validator validator;

	public EsLintRuleDesignerController(@Autowired EsLintRuleDesigner ruleDesigner,
			@Autowired RuleDesignerService ruleDesignerService,
			@Autowired EsLintRuleService ruleService) {
		this.ruleDesigner = ruleDesigner;
		this.ruleDesignerService = ruleDesignerService;
		this.ruleService = ruleService;
		this.validator = Validation.buildDefaultValidatorFactory().getValidator();
	}

	@PostMapping("query")
	public RuleDesignerModelAndView query(@RequestParam String sourceCode, EsLintRuleDto rule,
			Authentication auth) {
		RuleDesignerModelAndView mav = ruleDesigner
				.query(sourceCode, rule.isCore(), rule.getName(), rule.getCreateFunction(),
						rule.getMessages());
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
		return mav;
	}

	@PostMapping("save")
	public RuleDesignerModelAndView save(@RequestParam String sourceCode, EsLintRuleDto rule,
			Authentication auth) {
		// Run query to get ModelAndView
		RuleDesignerModelAndView mav = ruleDesigner
				.query(sourceCode, rule.isCore(), rule.getName(), rule.getCreateFunction(),
						rule.getMessages());
		mav.addObject("rule", rule);
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));

		// Add principal as author
		rule.setAuthor(auth.getName());
		// Validate rule
		Set<ConstraintViolation<EsLintRuleDto>> violations = validator.validate(rule);
		// Core rules are submitted without a message and without an external URL
		if (rule.isCore()) {
			violations = violations.stream()
					.filter(violation -> !(violation.getMessage().startsWith("Message")
							|| violation.getMessage().startsWith("External URL")))
					.collect(Collectors.toSet());
		}
		if (!violations.isEmpty()) {
			mav.addErrorMessage("Failed to validate rule. " + violations.stream()
					.map(ConstraintViolation::getMessage).collect(Collectors.joining(" ")));
			return mav;
		}

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
