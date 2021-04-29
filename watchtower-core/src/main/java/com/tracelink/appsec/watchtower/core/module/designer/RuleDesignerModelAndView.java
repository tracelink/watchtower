package com.tracelink.appsec.watchtower.core.module.designer;

import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

/**
 * This MAV provides a basic wrapper around the {@link WatchtowerModelAndView} in order to correctly
 * integrate the UI for a module's Rule Designer into the Watchtower UI
 * 
 * @author csmith
 *
 */
public class RuleDesignerModelAndView extends WatchtowerModelAndView {

	public RuleDesignerModelAndView(String designerView) {
		super("rules/designer");
		addObject("designerView", designerView);
		addScriptReference("/webjars/codemirror/5.60.0/lib/codemirror.js");
		addStyleReference("/webjars/codemirror/5.60.0/lib/codemirror.css");
	}

}
