package com.tracelink.appsec.watchtower.core.ruleset;

import java.io.IOException;
import java.security.Principal;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
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
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;
import com.tracelink.appsec.watchtower.core.scan.presentation.ScannerIdentity;

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
	private final ScanRegistrationService scanRegistrationService;
	private final RulesetPageService rulesetPage;

	public RulesetsController(@Autowired RulesetService rulesetService,
			@Autowired ScanRegistrationService scanRegistrationService,
			@Autowired RulesetPageService rulesetPage) {
		this.rulesetService = rulesetService;
		this.scanRegistrationService = scanRegistrationService;
		this.rulesetPage = rulesetPage;
	}

	private String makeRedirect(long id) {
		return RULESETS_REDIRECT + id;
	}

	@GetMapping("")
	public String getRulesets() {
		List<RulesetPageService.RulesetSummary> rulesets = rulesetPage.summaries();
		return RulesetPageService.defaultOf(rulesets).map(ruleset -> makeRedirect(ruleset.id()))
				.orElseGet(() -> makeRedirect(rulesets.isEmpty() ? -1 : rulesets.get(0).id()));
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

	/** What the chosen file would change; nothing is written. The dialog shows this before Import. */
	@PostMapping(value = {"/import/preview", "/{id}/import/preview"})
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_IMPEX_NAME + "')")
	@org.springframework.web.bind.annotation.ResponseBody
	public org.springframework.http.ResponseEntity<?> previewImport(@RequestParam MultipartFile file) {
		try {
			return org.springframework.http.ResponseEntity.ok(rulesetService.previewImport(file.getInputStream()));
		} catch (JsonProcessingException e) {
			LOG.info("Ruleset import preview could not parse the upload: {}", e.getOriginalMessage());
			return org.springframework.http.ResponseEntity.badRequest().body(java.util.Map.of("error",
					"This is not a Watchtower ruleset export. Use Export on a ruleset to get a compatible JSON file."));
		} catch (java.io.IOException e) {
			LOG.error("Could not read ruleset import preview upload", e);
			return org.springframework.http.ResponseEntity.badRequest().body(java.util.Map.of("error",
					"The file could not be read. Choose it again."));
		}
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

	/**
	 * One ruleset: summary chips, then its rules as one paged table with All / Its own / Included
	 * tabs and Scanner / Severity filters. Rules are read a page at a time (RulesetPageService);
	 * the page no longer builds every ruleset with every rule.
	 */
	@GetMapping("/{id}")
	public WatchtowerModelAndView getRulesetsView(@PathVariable long id,
			@RequestParam(defaultValue = RulesetPageService.ALL) String scope,
			@RequestParam(defaultValue = RulesetPageService.ALL) String scanner,
			@RequestParam(defaultValue = RulesetPageService.ALL) String severity,
			@RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "25") int pageSize,
			RedirectAttributes redirectAttributes) {
		WatchtowerModelAndView mv = new WatchtowerModelAndView("rules/rulesets");
		List<RulesetPageService.RulesetSummary> rulesets = rulesetPage.summaries();
		Optional<RulesetPageService.RulesetSummary> rulesetOpt =
				rulesets.stream().filter(r -> r.id().equals(id)).findFirst();
		if (id > -1 && !rulesetOpt.isPresent()) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Could not find a ruleset with id: " + id);
			mv.setViewName(getRulesets());
			return mv;
		}
		RulesetPageService.Filter filter;
		Map<String, ScannerIdentity> scanners = rulesetPage.knownScanners();
		try {
			filter = new RulesetPageService.Filter(scope, scanner, severity, page, pageSize);
			if (!RulesetPageService.ALL.equals(filter.scanner()) && !scanners.containsKey(filter.scanner())) {
				throw new IllegalArgumentException("Unknown scanner");
			}
		} catch (IllegalArgumentException invalid) {
			LOG.info("Rejected ruleset filters: {}", invalid.getMessage());
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Check the tab, scanner, severity and page.");
		}
		// null if there are no rulesets and you have to create/import one first
		RulesetPageService.RulesetView view = rulesetOpt
				.map(ruleset -> rulesetPage.view(ruleset, rulesets, filter, scanRegistrationService::isSensitiveModule))
				.orElse(null);
		mv.addObject("currentRuleset", rulesetOpt.orElse(null));
		mv.addObject("view", view);
		mv.addObject("filter", filter);
		mv.addObject("knownScanners", scanners);
		mv.addObject("secretsBlockingWarning", view != null && view.secretsMayNotBlock());
		mv.addObject("rulesets", rulesets);
		// Rule counts for the dialogs (default ruleset, included rulesets); the "Rules in …" dialog
		// loads its list on open from /rules/choices instead of every rule being rendered here.
		mv.addObject("ruleCounts", rulesetPage.ruleCounts(rulesets));
		mv.addObject("defaultRuleset", RulesetPageService.defaultOf(rulesets).orElse(null));
		mv.addObject("rulePriorities", RulePriority.values());
		mv.addObject("rulesetDesignations",
				/*
				 * Only add designations that users can create rulesets for, so no DEFAULT, and no
				 * PROVIDED
				 */
				Arrays.asList(RulesetDesignation.PRIMARY, RulesetDesignation.SUPPORTING));
		mv.addObject("pageUrl", rulesetOpt.map(ruleset -> UriComponentsBuilder.fromPath("/rulesets/{id}")
				.queryParam("scope", "{scope}").queryParam("scanner", "{scanner}")
				.queryParam("severity", "{severity}").queryParam("pageSize", "{pageSize}").encode()
				.buildAndExpand(Map.of("id", ruleset.id(), "scope", filter.scope(), "scanner", filter.scanner(),
						"severity", filter.severity(), "pageSize", filter.pageSize()))
				.toUriString()).orElse(null));
		mv.addScriptReference("/scripts/rulesets.js");
		return mv;
	}

	/**
	 * The "Rules in …" dialog's list, loaded when it opens: every rule as scalars (scanner, custom or
	 * provided, retired), ticked where this ruleset holds it, and the scanners for its filter.
	 */
	@GetMapping("/{id}/rules/choices")
	@PreAuthorize("hasAuthority('" + CorePrivilege.RULESETS_MODIFY_NAME + "')")
	@org.springframework.web.bind.annotation.ResponseBody
	public Map<String, Object> ruleChoices(@PathVariable long id) {
		if (rulesetPage.summaries().stream().noneMatch(ruleset -> ruleset.id().equals(id))) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No such ruleset");
		}
		List<RulesetPageService.RuleChoice> choices = rulesetPage.ruleChoices(id);
		Map<String, Map<String, String>> scanners = new java.util.TreeMap<>();
		choices.forEach(choice -> scanners.putIfAbsent(choice.scanner(),
				Map.of("key", choice.scanner(), "name", choice.scannerName(), "icon", choice.icon())));
		return Map.of("rules", choices, "scanners", List.copyOf(scanners.values()));
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
	public String deleteRuleset(@PathVariable long id, @RequestParam(required = false) String confirmName,
			RedirectAttributes redirectAttributes) {
		// The dialog asks for the name before Delete is enabled; the server checks it too.
		Optional<RulesetPageService.RulesetSummary> ruleset =
				rulesetPage.summaries().stream().filter(summary -> summary.id().equals(id)).findFirst();
		if (ruleset.isEmpty()) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot delete ruleset. It no longer exists.");
			return getRulesets();
		}
		if (confirmName == null || !confirmName.trim().equals(ruleset.get().name())) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot delete ruleset. Type its name to confirm.");
			return makeRedirect(id);
		}
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
