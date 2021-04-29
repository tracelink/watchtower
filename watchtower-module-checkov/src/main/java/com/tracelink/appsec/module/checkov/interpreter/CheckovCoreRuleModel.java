package com.tracelink.appsec.module.checkov.interpreter;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.tracelink.appsec.module.checkov.model.CheckovRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * The core rule model handles a core rule name and priority designation. The rest of the rule
 * information is pulled from Checkov directly
 * 
 * @author csmith
 *
 */
public class CheckovCoreRuleModel extends AbstractCheckovRuleModel {

	@JsonProperty("core")
	private String coreRuleName;

	@JsonProperty("priority")
	private int priority;


	public String getCoreRuleName() {
		return coreRuleName;
	}

	public void setCoreRuleName(String coreRuleName) {
		this.coreRuleName = coreRuleName;
	}

	public int getPriority() {
		return priority;
	}

	public void setPriority(int priority) {
		this.priority = priority;
	}

	@Override
	protected RuleDto toDto() {
		CheckovRuleDto rule = new CheckovRuleDto();
		rule.setName(getCoreRuleName());
		rule.setPriority(RulePriority.valueOf(getPriority()));
		return rule;
	}
}
