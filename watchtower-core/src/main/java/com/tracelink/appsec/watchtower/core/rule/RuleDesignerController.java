package com.tracelink.appsec.watchtower.core.rule;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
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

	public RuleDesignerController(@Autowired RuleDesignerService ruleDesignerService) {
		this.ruleDesignerService = ruleDesignerService;
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
			Authentication authentication, RedirectAttributes redirectAttributes) {
		RuleDesignerModelAndView rmav;

		try {
			rmav = ruleDesignerService.getDefaultDesignerModelAndView(designer);
			rmav.addObject("knownModules",
					ruleDesignerService.getKnownModulesForUser(authentication));
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
