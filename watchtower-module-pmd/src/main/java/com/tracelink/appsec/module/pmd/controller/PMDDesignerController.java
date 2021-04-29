package com.tracelink.appsec.module.pmd.controller;

import java.util.Arrays;
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

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.module.pmd.designer.PMDRuleDesigner;
import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.module.pmd.model.PMDRuleDto;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

import net.sourceforge.pmd.lang.rule.XPathRule;

/**
 * Controller to handle designing a PMD Rule
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + PMDModule.PMD_RULE_DESIGNER_PRIVILEGE_NAME + "')")
public class PMDDesignerController {

	private PMDRuleService ruleService;
	private PMDRuleDesigner ruleDesigner;
	private Validator validator;
	private RuleDesignerService ruleDesignerService;

	public PMDDesignerController(@Autowired PMDRuleService ruleService,
			@Autowired PMDRuleDesigner designerService,
			@Autowired RuleDesignerService ruleDesignerService) {
		this.ruleService = ruleService;
		this.ruleDesigner = designerService;
		this.validator = Validation.buildDefaultValidatorFactory().getValidator();
		this.ruleDesignerService = ruleDesignerService;
	}

	@PostMapping("/designer/pmd/save")
	public RuleDesignerModelAndView saveRule(@RequestParam String name,
			@RequestParam String message,
			@RequestParam String description, @RequestParam String language,
			@RequestParam int priority, @RequestParam String query,
			@RequestParam String externalUrl, String source, Authentication auth) {

		PMDRuleDto pmdDto = createPMDRuleDto(name, message, description, language, priority, query,
				externalUrl, auth);
		RuleDesignerModelAndView mav = ruleDesigner.query(language, query, source);

		Set<ConstraintViolation<PMDRuleDto>> violations = validator.validate(pmdDto);
		if (!violations.isEmpty()) {
			String vioMessage =
					violations.stream().map(ConstraintViolation::getMessage)
							.collect(Collectors.joining(", "));
			mav.addErrorMessage("Failed to validate. " + vioMessage);
			mav.addObject("ruleName", name);
			mav.addObject("ruleMessage", message);
			mav.addObject("ruleLanguage", language);
			mav.addObject("ruleDescription", description);
			mav.addObject("rulePriority", priority);
			mav.addObject("ruleExtUrl", externalUrl);
		} else {
			try {
				ruleService.saveNewRule(pmdDto);
				mav.addSuccessMessage("Created rule: " + pmdDto.getName());
			} catch (RuleDesignerException e) {
				mav.addErrorMessage("Cannot save rule. " + e.getMessage());
			}
		}
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
		return mav;
	}

	private PMDRuleDto createPMDRuleDto(String name, String message, String description,
			String language, int priority, String query, String externalUrl, Authentication auth) {
		PMDPropertyDto property = new PMDPropertyDto();
		property.setName("xpath");
		property.setValue(query);

		PMDRuleDto pmdDto = new PMDRuleDto();
		pmdDto.setAuthor(auth.getName());
		pmdDto.setDescription(description);
		pmdDto.setExternalUrl(externalUrl);
		pmdDto.setMessage(message);
		pmdDto.setName(name);
		pmdDto.setParserLanguage(language);
		pmdDto.setPriority(RulePriority.valueOf(priority));
		pmdDto.setRuleClass(XPathRule.class.getName());
		pmdDto.setProperties(Arrays.asList(property));
		return pmdDto;
	}

	@PostMapping("/designer/pmd/query")
	public RuleDesignerModelAndView query(@RequestParam String language, @RequestParam String query,
			@RequestParam String source, Authentication auth) {
		RuleDesignerModelAndView mav = ruleDesigner.query(language, query, source);
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
		return mav;

	}
}
