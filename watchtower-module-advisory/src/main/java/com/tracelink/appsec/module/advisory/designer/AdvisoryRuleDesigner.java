package com.tracelink.appsec.module.advisory.designer;

import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.advisory.AdvisoryModule;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;

/**
 * Service used to handle Rule Designer work
 * 
 * @author csmith
 *
 */
@Service
public class AdvisoryRuleDesigner implements IRuleDesigner {

	@Override
	public RuleDesignerModelAndView getDefaultRuleDesignerModelAndView() {
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView("designer/advisory");
		mav.addScriptReference("/scripts/advisory-designer.js");
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return AdvisoryModule.ADVISORY_RULE_DESIGNER_PRIVILEGE_NAME;
	}

}
