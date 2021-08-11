package com.tracelink.appsec.watchtower.core.ruleset;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleEditorService;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleService;

/**
 * Controller for operations to view rules assigned to {@link RulesetEntity}. Admins can also edit
 * the rules assigned.
 *
 * @author mcool
 */
@Controller
@RequestMapping("/rulesets")
@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_VIEW_NAME + "')")
public class RulesetsController {

	private static final Logger LOG = LoggerFactory.getLogger(RulesetsController.class);
	private static final String RULESETS_REDIRECT = "redirect:/rulesets/";

	private RulesetService rulesetService;
	private RuleEditorService ruleManagerService;
	private RuleService ruleService;

	public RulesetsController(@Autowired RulesetService rulesetService,
			@Autowired RuleEditorService ruleManagerService,
			@Autowired RuleService ruleService) {
		this.rulesetService = rulesetService;
		this.ruleManagerService = ruleManagerService;
		this.ruleService = ruleService;
	}

	private String makeRedirect(long id) {
		return RULESETS_REDIRECT + id + "/";
	}

	@GetMapping("")
	public String getRulesets() {
		RulesetEntity ruleset = rulesetService.getDefaultRuleset();
		if (ruleset == null) {
			List<RulesetDto> rulesets = rulesetService.getRulesets();
			if (rulesets.isEmpty()) {
				return makeRedirect(-1);
			}
			return makeRedirect(rulesets.get(0).getId());
		}
		return makeRedirect(ruleset.getId());
	}

	@PostMapping(value = {"/create", "/{id}/create"})
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_MODIFY_NAME + "')")
	public String createRuleset(@PathVariable Optional<Long> id, @RequestParam String name,
			@RequestParam String description, @RequestParam RulesetDesignation designation,
			RedirectAttributes redirectAttributes) {
		String redirect;
		try {
			if (designation.equals(RulesetDesignation.PROVIDED)) {
				throw new RulesetException("Cannot create a provided ruleset");
			}
			RulesetEntity ruleset = rulesetService.createRuleset(name, description, designation);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully created ruleset.");
			redirect = makeRedirect(ruleset.getId());
		} catch (IllegalArgumentException | RulesetException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot create ruleset. " + e.getMessage());
			redirect = id.isPresent() ? makeRedirect(id.get()) : getRulesets();
		}
		return redirect;
	}

	@PostMapping(value = {"/default", "/{id}/default"})
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_MODIFY_NAME + "')")
	public String setDefaultRuleset(@PathVariable Optional<Long> id,
			@RequestParam(required = false, defaultValue = "-1") long rulesetId,
			RedirectAttributes redirectAttributes) {
		try {
			RulesetDto dto = rulesetService.setDefaultRuleset(rulesetId).toDto();
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully set the default ruleset.");
			id = Optional.of(dto.getId());
		} catch (RulesetNotFoundException | RulesetException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot set the default ruleset. " + e.getMessage());
		}
		return id.isPresent() ? makeRedirect(id.get()) : getRulesets();
	}

	@PostMapping(value = {"/import", "/{id}/import"})
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_IMPEX_NAME + "')")
	public String importRuleset(@PathVariable Optional<Long> id, @RequestParam MultipartFile file,
			Principal authenticatedUser, RedirectAttributes redirectAttributes) {
		try {
			RulesetDto newRuleset = rulesetService.importRuleset(file.getInputStream(),
					authenticatedUser.getName());
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully imported ruleset.");
			id = Optional.of(newRuleset.getId());
		} catch (JsonProcessingException e) {
			LOG.error("Exception parsing ruleset for import", e);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot import ruleset. Error parsing upload.");
		} catch (Exception e) {
			LOG.error("Exception importing ruleset", e);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot import ruleset. Please check the log for more details.");
		}
		return id.isPresent() ? makeRedirect(id.get()) : getRulesets();
	}

	@GetMapping("/{id}")
	public WatchtowerModelAndView getRulesetsView(@PathVariable long id,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("rules/rulesets");
		List<RulesetDto> rulesets = rulesetService.getRulesets();
		Optional<RulesetDto> rulesetOpt =
				rulesets.stream().filter(r -> r.getId().equals(id)).findFirst();
		if (id > -1 && !rulesetOpt.isPresent()) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Could not find a ruleset with id: " + id);
			mv.setViewName(getRulesets());
			return mv;
		}
		// null if there are no rulesets and you have to create/import one first
		mv.addObject("currentRuleset", rulesetOpt.orElse(null));
		mv.addObject("rulesets", rulesets);
		mv.addObject("rules", ruleService.getRules());
		mv.addObject("defaultRuleset", rulesetService.getDefaultRuleset());
		mv.addObject("ruleTypes", ruleManagerService.getKnownModules());
		mv.addObject("rulePriorities", RulePriority.values());
		mv.addObject("rulesetDesignations",
				/*
				 * Only add designations that users can create rulesets for, so no DEFAULT, and no
				 * PROVIDED
				 */
				Arrays.asList(RulesetDesignation.PRIMARY, RulesetDesignation.SUPPORTING));
		mv.addScriptReference("/scripts/rulesets.js");
		return mv;
	}

	@PostMapping("/{id}/rules")
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_MODIFY_NAME + "')")
	public String setRules(@PathVariable long id,
			@RequestParam(required = false, defaultValue = "") List<Long> ruleIds,
			RedirectAttributes redirectAttributes) {
		try {
			rulesetService.setRules(id, ruleIds);
			redirectAttributes
					.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
							"Successfully set rules.");
		} catch (RulesetNotFoundException | RuleNotFoundException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot set rules. " + e.getMessage());
		}
		return makeRedirect(id);
	}

	@PostMapping("/{id}/export")
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_IMPEX_NAME + "')")
	public void exportRuleset(@PathVariable long id, HttpServletResponse response) {
		try {
			rulesetService.exportRuleset(id, response);
		} catch (RulesetNotFoundException | RulesetException | IOException e) {
			LOG.error("Error exporting ruleset with ID: " + id, e);
		}
	}

	@PostMapping("/{id}/delete")
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_MODIFY_NAME + "')")
	public String deleteRuleset(@PathVariable long id,
			RedirectAttributes redirectAttributes) {
		String redirect;
		try {
			rulesetService.deleteRuleset(id);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully deleted ruleset.");
			redirect = getRulesets();
		} catch (RulesetNotFoundException | RulesetException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot delete ruleset. " + e.getMessage());
			redirect = makeRedirect(id);
		}
		return redirect;
	}

	@PostMapping("/{id}/edit")
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_MODIFY_NAME + "')")
	public String editRuleset(@PathVariable long id, @Valid RulesetDto rulesetDto,
			BindingResult bindingResult, RedirectAttributes redirectAttributes) {
		// Validate ruleset
		if (bindingResult.hasErrors()) {
			FieldError error = bindingResult.getFieldErrors().get(0);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit ruleset. " + error.getDefaultMessage());
			return makeRedirect(id);
		}
		if (id != rulesetDto.getId()) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit a different ruleset than you are currently viewing");
			return makeRedirect(id);
		}

		try {
			rulesetService.editRuleset(rulesetDto);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully edited ruleset.");
		} catch (RulesetNotFoundException | IllegalArgumentException | RulesetException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot edit ruleset. " + e.getMessage());
		}
		return makeRedirect(id);
	}

	@PostMapping("/{id}/inherit")
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_MODIFY_NAME + "')")
	public String setInheritedRulesets(@PathVariable long id,
			@RequestParam(required = false, defaultValue = "") List<Long> inheritedRulesetIds,
			RedirectAttributes redirectAttributes) {
		try {
			rulesetService.setInheritedRulesets(id, inheritedRulesetIds);
			redirectAttributes
					.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
							"Successfully set inherited rulesets.");
		} catch (RulesetNotFoundException | RulesetException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot set inherited rulesets. " + e.getMessage());
		}
		return makeRedirect(id);
	}

}
