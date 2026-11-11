package com.tracelink.appsec.watchtower.core.rule;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.rule.draft.RuleDraftBanner;
import com.tracelink.appsec.watchtower.core.rule.draft.RuleDraftService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/**
 * Controller to map requests and defer their implementation to a module's desired User Experience.
 * 
 * @author csmith
 *
 */
@Controller
@PreAuthorize("hasAuthority('" + CorePrivilege.RULE_DESIGNER_NAME + "')")
public class RuleDesignerController {

	private RuleDesignerService ruleDesignerService;
	private RuleDraftService drafts;

	public RuleDesignerController(@Autowired RuleDesignerService ruleDesignerService,
			@Autowired RuleDraftService drafts) {
		this.ruleDesignerService = ruleDesignerService;
		this.drafts = drafts;
	}

	@GetMapping("/designer")
	public String getDesigner(RedirectAttributes redirectAttributes) {
		String type = ruleDesignerService.getDefaultDesignerModule();
		if (type == null) {
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"There are no designers configured in Watchtower");
			return "redirect:/";
		}
		return "redirect:/designer/" + type.toLowerCase();
	}

	@GetMapping("/designer/{designer}")
	public WatchtowerModelAndView getDesignerByModule(@PathVariable String designer,
			@RequestParam(required = false) String draft, Authentication authentication,
			RedirectAttributes redirectAttributes) {
		RuleDesignerModelAndView rmav;

		try {
			// A draft opens only for the person it belongs to, in the designer it was made for; anything else is the plain page.
			Optional<RuleDraftData> drafted = draft == null ? Optional.empty()
					: drafts.open(draft, authentication.getName(), designer);
			rmav = drafted.isPresent()
					? ruleDesignerService.getPrefilledDesignerModelAndView(designer, drafted.get())
					: ruleDesignerService.getDefaultDesignerModelAndView(designer);
			if (drafted.isPresent()) {
				rmav.addObject("draftBanner", RuleDraftBanner.of(drafted.get()));
			} else if (draft != null) {
				rmav.addObject(WatchtowerModelAndView.FAILURE_NOTIFICATION,
						"That draft is no longer available: it was used, discarded or has expired.");
			}
			rmav.addObject("knownModules",
					ruleDesignerService.getKnownModulesForUser(authentication));
			rmav.addObject("currentDesigner", designer.toLowerCase());
			rmav.addObject("moduleFileTypes", ruleDesignerService.getFileTypes(designer));
		} catch (ModuleNotFoundException e) {
			WatchtowerModelAndView wmav = new WatchtowerModelAndView("");
			wmav.setViewName("redirect:/designer");
			redirectAttributes.addFlashAttribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
					"Unknown Designer");
			return wmav;
		}
		return rmav;
	}

}
