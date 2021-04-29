package com.tracelink.appsec.watchtower.core.ruleset;

import java.io.IOException;
import java.security.Principal;
import java.util.List;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.module.interpreter.RulesetInterpreterException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleEditorService;
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
	private static final String RULESETS_REDIRECT = "redirect:/rulesets";

	private RulesetService rulesetService;
	private RuleEditorService ruleManagerService;
	private RuleService ruleService;
	private UserService userService;

	public RulesetsController(@Autowired RulesetService rulesetService,
			@Autowired RuleEditorService ruleManagerService,
			@Autowired RuleService ruleService,
			@Autowired UserService userService) {
		this.rulesetService = rulesetService;
		this.ruleManagerService = ruleManagerService;
		this.ruleService = ruleService;
		this.userService = userService;
	}

	@GetMapping("")
	public WatchtowerModelAndView getRulesets(
			@RequestParam(required = false, defaultValue = "-1") long activeRuleset) {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("rules/rulesets");
		List<RulesetDto> rulesets = rulesetService.getRulesets();
		mv.addObject("rulesets", rulesets);
		mv.addObject("rules", ruleService.getRules());
		mv.addObject("activeRuleset", getActiveRuleset(activeRuleset, rulesets));
		mv.addObject("ruleTypes", ruleManagerService.getKnownModules());
		mv.addScriptReference("/scripts/ruleset-composition.js");
		return mv;
	}

	@PostMapping("")
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_MODIFY_NAME + "')")
	public String setRules(@RequestParam long rulesetId,
			@RequestParam(required = false, defaultValue = "") List<Long> ruleIds,
			RedirectAttributes redirectAttributes) {
		try {
			rulesetService.setRules(rulesetId, ruleIds);
			redirectAttributes
					.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
							"Successfully set rules.");
		} catch (RulesetNotFoundException | RuleNotFoundException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot set rules. " + e.getMessage());
		}
		return RULESETS_REDIRECT + "?activeRuleset=" + rulesetId;
	}

	@PostMapping("/import")
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_MODIFY_NAME + "')")
	public String importRuleset(@RequestParam String ruleType, @RequestParam MultipartFile file,
			Principal authenticatedUser, RedirectAttributes redirectAttributes) {
		try {
			rulesetService.importRuleset(ruleType, file.getInputStream(),
					userService.findByUsername(authenticatedUser.getName()));
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
					"Successfully imported ruleset.");
		} catch (JsonProcessingException e) {
			LOG.error("Exception parsing ruleset for import", e);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot import ruleset. Error parsing upload.");
		} catch (Exception e) {
			LOG.error("Exception importing ruleset", e);
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot import ruleset. Please check the log for more details.");
		}
		return RULESETS_REDIRECT;
	}

	@PostMapping("/export")
	public void exportRuleset(@RequestParam long rulesetId, HttpServletResponse response) {
		try {
			rulesetService.exportRuleset(rulesetId, response);
		} catch (RulesetNotFoundException | RulesetException | IOException
				| RulesetInterpreterException e) {
			LOG.error("Error exporting ruleset with ID: " + rulesetId, e);
		}
	}

	@GetMapping(value = "/import/example", produces = MediaType.APPLICATION_OCTET_STREAM_VALUE)
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_MODIFY_NAME + "')")
	public ResponseEntity<InputStreamResource> downloadImportExample(
			@RequestParam String ruleType) {
		InputStreamResource res = null;
		try {

			if (StringUtils.isBlank(ruleType)) {
				throw new RulesetInterpreterException("No Rule Type selected");
			}

			res = rulesetService.downloadExampleRuleset(ruleType);

			if (res == null) {
				throw new RulesetInterpreterException("Cannot Export Example Ruleset");
			}
		} catch (Exception e) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
		}

		return ResponseEntity.ok()
				.header("Content-Disposition",
						"attachment; filename=\"" + res.getFilename() + "\"")
				.contentType(MediaType.APPLICATION_OCTET_STREAM)
				.body(res);
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
