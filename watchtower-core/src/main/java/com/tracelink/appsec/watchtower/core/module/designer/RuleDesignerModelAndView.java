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
		// CodeMirror 6 injects its own <style> tags at runtime; unlike CodeMirror 5,
		// there is no separate stylesheet to reference here.
		addScriptReference("/scripts/codemirror-bundle.js");
		addScriptReference("/scripts/rule-designer.js");
		addScriptReference("/scripts/designer-file-types.js");
	}

}
