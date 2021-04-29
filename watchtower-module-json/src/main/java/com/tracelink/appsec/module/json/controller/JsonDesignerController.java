package com.tracelink.appsec.module.json.controller;

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

import com.tracelink.appsec.module.json.JsonModule;
import com.tracelink.appsec.module.json.designer.JsonRuleDesigner;
import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.module.json.service.JsonRuleService;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Controller to handle designing a JSON Rule
 *
 * @author csmith
 */
@Controller
@PreAuthorize("hasAuthority('" + JsonModule.JSON_RULE_DESIGNER_PRIVILEGE_NAME + "')")
public class JsonDesignerController {

	private JsonRuleService ruleService;
	private Validator validator;
	private JsonRuleDesigner designerService;
	private RuleDesignerService ruleDesignerService;

	public JsonDesignerController(@Autowired JsonRuleService ruleService,
			@Autowired JsonRuleDesigner designerService,
			@Autowired RuleDesignerService ruleDesignerService) {
		this.ruleService = ruleService;
		this.validator = Validation.buildDefaultValidatorFactory().getValidator();
		this.designerService = designerService;
		this.ruleDesignerService = ruleDesignerService;
	}

	@PostMapping("/designer/json/save")
	public RuleDesignerModelAndView saveRule(@RequestParam String name,
			@RequestParam String message,
			@RequestParam String fileExtension, @RequestParam int priority,
			@RequestParam String query, @RequestParam String externalUrl,
			@RequestParam String code, Authentication auth,
			RedirectAttributes redirectAttributes) {

		JsonRuleDto ruleDto = createJsonRuleDto(name, message, fileExtension, priority, query,
				externalUrl, auth);
		RuleDesignerModelAndView mav = designerService.query(query, code);

		Set<ConstraintViolation<JsonRuleDto>> violations = validator.validate(ruleDto);
		String vioMessage = "";
		try {
			ruleDto.getCompiledQuery();
		} catch (Exception e) {
			vioMessage = e.getMessage();
		}
		if (!violations.isEmpty() || !vioMessage.isEmpty()) {
			vioMessage +=
					violations.stream().map(v -> v.getMessage()).collect(Collectors.joining(", "));
			mav.addErrorMessage("Failed to validate. " + vioMessage);
			mav.addObject("ruleName", name);
			mav.addObject("ruleMessage", message);
			mav.addObject("ruleFileExt", fileExtension);
			mav.addObject("rulePriority", priority);
			mav.addObject("ruleExtUrl", externalUrl);
		} else {

			try {
				ruleService.saveNewRule(ruleDto);
				mav.addSuccessMessage("Created rule: " + ruleDto.getName());
			} catch (RuleDesignerException e) {
				mav.addErrorMessage("Cannot save rule. " + e.getMessage());
			}
		}
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
		return mav;
	}

	private JsonRuleDto createJsonRuleDto(String name, String message, String fileExtension,
			int priority, String query, String externalUrl, Authentication auth) {
		JsonRuleDto jsonDto = new JsonRuleDto();
		jsonDto.setAuthor(auth.getName());
		jsonDto.setExternalUrl(externalUrl);
		jsonDto.setMessage(message);
		jsonDto.setName(name);
		jsonDto.setPriority(RulePriority.valueOf(priority));
		jsonDto.setFileExtension(fileExtension);
		jsonDto.setQuery(query);
		return jsonDto;
	}

	@PostMapping("/designer/json/query")
	public RuleDesignerModelAndView query(@RequestParam String query, @RequestParam String code,
			Authentication auth) {
		RuleDesignerModelAndView mav = designerService.query(query, code);
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
		return mav;
	}
}
