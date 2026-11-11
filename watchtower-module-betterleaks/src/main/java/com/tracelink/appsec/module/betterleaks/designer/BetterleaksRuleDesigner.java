package com.tracelink.appsec.module.betterleaks.designer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksRuleTestResult;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksCustomRuleDto;
import com.tracelink.appsec.module.betterleaks.service.BetterleaksRuleTester;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * The Betterleaks custom-rule designer: write a rule, run it against a sample it must match and
 * one it must not, and save it once it passes.
 *
 * @author Watchtower
 */
@Service
public class BetterleaksRuleDesigner implements IRuleDesigner {

	static final String DESIGNER_VIEW = "designer/betterleaks";

	private final BetterleaksRuleTester tester;

	public BetterleaksRuleDesigner(@Autowired BetterleaksRuleTester tester) {
		this.tester = tester;
	}

	@Override
	public RuleDesignerModelAndView getDefaultRuleDesignerModelAndView() {
		return view(exampleForm());
	}

	/**
	 * Tests the form's rule against its samples.
	 *
	 * @param form the submitted rule
	 * @return the designer showing the form and the result
	 */
	public RuleDesignerModelAndView test(BetterleaksCustomRuleForm form) {
		RuleDesignerModelAndView mav = view(form);
		BetterleaksRuleTestResult result;
		try {
			BetterleaksCustomRuleDto rule = form.toRule();
			result = tester.test(rule);
		} catch (IllegalArgumentException e) {
			result = BetterleaksRuleTestResult.problem(e.getMessage());
		}
		mav.addObject("result", result);
		return mav;
	}

	/**
	 * @param form the form to show
	 * @return the designer view for it
	 */
	public RuleDesignerModelAndView view(BetterleaksCustomRuleForm form) {
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView(DESIGNER_VIEW);
		mav.addObject("form", form);
		mav.addObject("priorities", RulePriority.values());
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return BetterleaksModule.RULE_DESIGNER_PRIVILEGE_NAME;
	}

	private static BetterleaksCustomRuleForm exampleForm() {
		BetterleaksCustomRuleForm form = new BetterleaksCustomRuleForm();
		form.setRuleId("custom-example-token");
		form.setDescription("An example internal token. Rotate it and move it to the secret"
				+ " manager.");
		form.setPriority(RulePriority.HIGH.name());
		form.setRegex("exmpl_[A-Za-z0-9]{24}");
		form.setKeywords("exmpl_");
		form.setEntropy("3.5");
		form.setPositiveSample("token = \"exmpl_" + "Q7m2Zp9Xc4Vb8Nn1Lk3Jh5Gf\"");
		form.setNegativeSample("token = \"exmpl_placeholder\"");
		return form;
	}
}
