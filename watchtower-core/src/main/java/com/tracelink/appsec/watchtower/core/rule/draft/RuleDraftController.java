package com.tracelink.appsec.watchtower.core.rule.draft;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/** Throws away a drafted rule from the designer page. Only its author can; nothing else changes. */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.RULE_DESIGNER_NAME + "')")
public class RuleDraftController {
	private final RuleDraftService drafts;

	public RuleDraftController(RuleDraftService drafts) {
		this.drafts = drafts;
	}

	/**
	 * The page goes back to the plain designer of the draft's own scanner. That name comes from the stored
	 * draft and is one of a fixed list, never from the request.
	 */
	@PostMapping("/designer/draft/{id}/discard")
	public String discard(@PathVariable String id, Authentication user, RedirectAttributes redirect) {
		String engine = drafts.ownedOpen(id, user.getName()).map(RuleDraftData::engine)
				.filter(RuleDraftService.ENGINES::contains).orElse(null);
		if (engine == null || !drafts.discard(id, user.getName())) {
			redirect.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"That draft is no longer available: it was used, discarded or has expired.");
			return "redirect:/designer";
		}
		redirect.addFlashAttribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION, "Draft discarded.");
		return switch (engine) {
			case "opengrep" -> "redirect:/designer/opengrep";
			case "regex" -> "redirect:/designer/regex";
			case "pmd" -> "redirect:/designer/pmd";
			case "json" -> "redirect:/designer/json";
			default -> "redirect:/designer/eslint";
		};
	}
}
