package com.tracelink.appsec.module.advisory.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.module.advisory.AdvisoryModule;
import com.tracelink.appsec.module.advisory.designer.AdvisoryRuleDesigner;
import com.tracelink.appsec.module.advisory.model.AdvisoryRuleDto;
import com.tracelink.appsec.module.advisory.service.AdvisoryRuleService;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.service.ImageAdvisoryService;

@Controller
@RequestMapping("/designer/advisory")
@PreAuthorize("hasAuthority('" + AdvisoryModule.ADVISORY_RULE_DESIGNER_PRIVILEGE_NAME + "')")
public class AdvisoryDesignerController {

	private ImageAdvisoryService imageAdvisoryService;

	private AdvisoryRuleDesigner designerService;

	private AdvisoryRuleService ruleService;

	private RuleDesignerService ruleDesignerService;

	public AdvisoryDesignerController(@Autowired ImageAdvisoryService imageAdvisoryService,
			@Autowired AdvisoryRuleDesigner designerService,
			@Autowired AdvisoryRuleService ruleService,
			@Autowired RuleDesignerService ruleDesignerService) {
		this.imageAdvisoryService = imageAdvisoryService;
		this.designerService = designerService;
		this.ruleDesignerService = ruleDesignerService;
		this.ruleService = ruleService;
	}

	@PostMapping("/save")
	public RuleDesignerModelAndView saveRule(@RequestParam String advisoryName,
			Authentication auth, RedirectAttributes redirectAttributes) {
		RuleDesignerModelAndView mav = designerService.getDefaultRuleDesignerModelAndView();
		AdvisoryRuleDto ruleDto = createRuleDto(advisoryName, auth);
		try {
			ruleService.saveNewRule(ruleDto);
			mav.addSuccessMessage("Successfully Saved Rule " + ruleDto.getName());
		} catch (RuleDesignerException e) {
			mav.addErrorMessage(e.getMessage());
		}
		mav.addObject("knownModules", ruleDesignerService.getKnownModulesForUser(auth));
		return mav;
	}

	private AdvisoryRuleDto createRuleDto(String advisoryName, Authentication auth) {
		AdvisoryRuleDto dto = new AdvisoryRuleDto();
		AdvisoryEntity entity = imageAdvisoryService.findByName(advisoryName);
		dto.setAuthor(auth.getName());
		dto.setExternalUrl(entity.getUri());
		dto.setMessage(entity.getDescription());
		dto.setName(entity.getAdvisoryName());
		dto.setPriority(RulePriority.HIGH); // This value is ignored
		return dto;
	}
}
