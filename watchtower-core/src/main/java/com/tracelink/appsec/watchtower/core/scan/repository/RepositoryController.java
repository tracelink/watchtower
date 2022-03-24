package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.api.ApiIntegrationException;

/**
 * Controller for displaying repositories and their rulesets as well as changing rulesets
 *
 * @author csmith
 */
@Controller
@RequestMapping("/repository")
@PreAuthorize("hasAuthority('" + CorePrivilege.REPO_SETTINGS_VIEW_NAME + "')")
public class RepositoryController {

	private RepositoryService repoService;

	private RulesetService rulesetService;

	public RepositoryController(@Autowired RepositoryService repoService,
			@Autowired RulesetService rulesetService) {
		this.repoService = repoService;
		this.rulesetService = rulesetService;
	}

	@GetMapping("")
	public WatchtowerModelAndView repositoryScreen() {
		WatchtowerModelAndView mav = new WatchtowerModelAndView("configuration/repository");
		mav.addObject("repos", repoService.getAllRepos());
		mav.addObject("rulesets",
				rulesetService.getRulesets().stream().filter(r -> r.isPrimary())
						.collect(Collectors.toList()));
		mav.addScriptReference("/scripts/reposwitcher.js");
		return mav;
	}

	@PostMapping("")
	@PreAuthorize("hasAuthority('" + CorePrivilege.REPO_SETTINGS_MODIFY_NAME + "')")
	public String setRulesetForRepo(@RequestParam String apiLabel, @RequestParam String repo,
			@RequestParam long rulesetId, RedirectAttributes redirectAttributes) {
		try {
			repoService.setRulesetForRepo(rulesetId, apiLabel, repo);
		} catch (RulesetNotFoundException | RulesetException | ApiIntegrationException e) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Cannot set ruleset. " + e.getMessage());
		}
		return "redirect:/repository";
	}
}
