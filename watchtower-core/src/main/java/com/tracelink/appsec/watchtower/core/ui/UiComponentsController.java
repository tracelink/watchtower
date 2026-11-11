package com.tracelink.appsec.watchtower.core.ui;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/** Provides an internal, permission-gated reference for Watchtower's shared UI system. */
@Controller
public class UiComponentsController {

	@GetMapping("/admin/ui/components")
	@PreAuthorize("hasAuthority('" + CorePrivilege.ROLE_VIEW_NAME + "')")
	public WatchtowerModelAndView components() {
		return new WatchtowerModelAndView("admin/ui-components");
	}
}
