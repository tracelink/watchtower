package com.tracelink.appsec.watchtower.core.ui;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/** Makes feature instructions available independently of optional assistant activation. */
@Controller
public class FeatureGuideController {

	@GetMapping("/help/features")
	@PreAuthorize("isAuthenticated()")
	public WatchtowerModelAndView features() {
		return new WatchtowerModelAndView("help/features")
				.addScriptReference("/scripts/feature-guide.js");
	}
}
