package com.tracelink.appsec.module.regex.controller;

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
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.module.regex.RegexModule;
import com.tracelink.appsec.module.regex.designer.RegexRuleDesigner;
import com.tracelink.appsec.module.regex.model.RegexRuleDto;
import com.tracelink.appsec.module.regex.service.RegexRuleService;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Controller to handle designing a Regex Rule
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + RegexModule.REGEX_RULE_DESIGNER_PRIVILEGE_NAME + "')")
public class RegexDesignerController {

	private RegexRuleService ruleService;
	private Validator validator;
	private RegexRuleDesigner designerService;
	private RuleDesignerService ruleDesignerService;

	public RegexDesignerController(@Autowired RegexRuleService ruleService,
			@Autowired RegexRuleDesigner designerService,
			@Autowired RuleDesignerService ruleDesignerService) {
		this.ruleService = ruleService;
		this.validator = Validation.buildDefaultValidatorFactory().getValidator();
		this.designerService = designerService;
		this.ruleDesignerService = ruleDesignerService;
	}

	@PostMapping("/designer/regex/save")
	public RuleDesignerModelAndView saveRule(@RequestParam String name,
			@RequestParam String message,
			@RequestParam String fileExtension, @RequestParam int priority,
			@RequestParam String query, @RequestParam String externalUrl,
			@RequestParam String source, Authentication auth,
			RedirectAttributes redirectAttributes) {

		RegexRuleDto regexDto = createRegexRuleDto(name, message, fileExtension, priority, query,
				externalUrl, auth);
		RuleDesignerModelAndView mav = designerService.query(query, source);

		Set<ConstraintViolation<RegexRuleDto>> violations = validator.validate(regexDto);
		if (!violations.isEmpty()) {
			String vioMessage =
					violations.stream().map(ConstraintViolation::getMessage)
							.collect(Collectors.joining(", "));
			mav.addErrorMessage("Failed to validate. " + vioMessage);
			mav.addObject("ruleName", name);
			mav.addObject("ruleMessage", message);
			mav.addObject("ruleFileExt", fileExtension);
			mav.addObject("rulePriority", priority);
			mav.addObject("ruleExtUrl", externalUrl);
		} else {

			try {
				ruleService.saveNewRule(regexDto);
				mav.addSuccessMessage("Created rule: " + regexDto.getName());
			} catch (RuleDesignerException e) {
				mav.addErrorMessage("Cannot save rule. " + e.getMessage());
			}
		}
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
		return mav;
	}

	private RegexRuleDto createRegexRuleDto(String name, String message, String fileExtension,
			int priority, String query, String externalUrl, Authentication auth) {
		RegexRuleDto regexDto = new RegexRuleDto();
		regexDto.setAuthor(auth.getName());
		regexDto.setExternalUrl(externalUrl);
		regexDto.setMessage(message);
		regexDto.setName(name);
		regexDto.setPriority(RulePriority.valueOf(priority));
		regexDto.setFileExtension(fileExtension);
		regexDto.setRegexPattern(query);
		return regexDto;
	}

	@PostMapping("/designer/regex/query")
	public RuleDesignerModelAndView query(@RequestParam String query, @RequestParam String source,
			Authentication auth) {
		RuleDesignerModelAndView mav = designerService.query(query, source);
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
		return mav;
	}
}
