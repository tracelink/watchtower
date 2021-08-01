package com.tracelink.appsec.watchtower.core.ruleset;

import java.util.Arrays;
import java.util.List;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Controller for operations to create, delete, or edit {@link RulesetEntity}s. Also contains
 * endpoints to add or remove inherited rulesets.
 *
 * @author mcool
 */
@Controller
@RequestMapping("/ruleset/mgmt")
@PreAuthorize("hasAuthority('" + CorePrivilege.RULESET_MGMT_MODIFY_NAME + "')")
public class RulesetMgmtController {
	private static final String RULESET_MGMT_REDIRECT = "redirect:/ruleset/mgmt";

	private RulesetService rulesetService;

	public RulesetMgmtController(@Autowired RulesetService rulesetService) {
		this.rulesetService = rulesetService;
	}

	@GetMapping("")
	public WatchtowerModelAndView getRulesetMgmt(
			@RequestParam(required = false, defaultValue = "-1") long activeRuleset) {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("rules/ruleset-mgmt");
		List<RulesetDto> rulesets = rulesetService.getRulesets();
		mv.addObject("rulesets", rulesets);
		mv.addObject("activeRuleset", getActiveRuleset(activeRuleset, rulesets));
		mv.addObject("defaultRuleset", rulesetService.getDefaultRuleset());
		mv.addObject("rulesetDesignations",
				Arrays.asList(RulesetDesignation.PRIMARY, RulesetDesignation.SUPPORTING,
						RulesetDesignation.PROVIDED));
		mv.addObject("rulePriorities", RulePriority.values());
		mv.addScriptReference("/scripts/ruleset-mgmt.js");
		return mv;
	}

	@PostMapping("/create")
	public String createRuleset(@RequestParam String name, @RequestParam String description,
			@RequestParam RulesetDesignation designation, RedirectAttributes redirectAttributes) {
		String redirect = RULESET_MGMT_REDIRECT;
		try {
			RulesetEntity ruleset = rulesetService.createRuleset(name, description, designation);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully created ruleset.");
			redirect += "?activeRuleset=" + ruleset.getId();
		} catch (IllegalArgumentException | RulesetException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot create ruleset. " + e.getMessage());
		}
		return redirect;
	}

	@PostMapping("/delete")
	public String deleteRuleset(@RequestParam long rulesetId,
			RedirectAttributes redirectAttributes) {
		try {
			rulesetService.deleteRuleset(rulesetId);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully deleted ruleset.");
		} catch (RulesetNotFoundException | RulesetException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot delete ruleset. " + e.getMessage());
		}
		return RULESET_MGMT_REDIRECT;
	}

	@PostMapping("/edit")
	public String editRuleset(@Valid RulesetDto rulesetDto, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		// Validate ruleset
		if (bindingResult.hasErrors()) {
			FieldError error = bindingResult.getFieldErrors().get(0);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit ruleset. " + error.getDefaultMessage());
			return RULESET_MGMT_REDIRECT;
		}

		try {
			rulesetService.editRuleset(rulesetDto);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully edited ruleset.");
		} catch (RulesetNotFoundException | IllegalArgumentException | RulesetException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit ruleset. " + e.getMessage());
		}
		return RULESET_MGMT_REDIRECT + "?activeRuleset=" + rulesetDto.getId();
	}

	@PostMapping("/inherit")
	public String setInheritedRulesets(@RequestParam long rulesetId,
			@RequestParam(required = false, defaultValue = "") List<Long> inheritedRulesetIds,
			RedirectAttributes redirectAttributes) {
		try {
			rulesetService.setInheritedRulesets(rulesetId, inheritedRulesetIds);
			redirectAttributes
					.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
							"Successfully set inherited rulesets.");
		} catch (RulesetNotFoundException | RulesetException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot set inherited rulesets. " + e.getMessage());
		}
		return RULESET_MGMT_REDIRECT + "?activeRuleset=" + rulesetId;
	}

	@PostMapping("/default")
	public String setDefaultRuleset(
			@RequestParam(required = false, defaultValue = "-1") long rulesetId,
			RedirectAttributes redirectAttributes) {
		try {
			rulesetService.setDefaultRuleset(rulesetId);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully set the default ruleset.");
		} catch (RulesetNotFoundException | RulesetException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot set the default ruleset. " + e.getMessage());
		}
		return RULESET_MGMT_REDIRECT + "?activeRuleset=" + rulesetId;
	}

	private Long getActiveRuleset(Long rulesetId, List<RulesetDto> rulesets) {
		final Long finalRulesetId = rulesetId;
		// Check that the given ruleset is a valid ruleset
		if (finalRulesetId != null
				&& rulesets.stream().noneMatch(r -> r.getId().equals(finalRulesetId))) {
			rulesetId = null;
		}
		// If no given ruleset, set the first ruleset as active
		if (rulesetId == null && !rulesets.isEmpty()) {
			rulesetId = rulesets.get(0).getId();
		}
		return rulesetId;
	}
}
