package com.tracelink.appsec.watchtower.core.scan.image.ecr;

import java.util.List;

import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

public class EcrSecurityReport {

	private List<EcrSecurityFinding> findings;



	public EcrSecurityReport filterByAllowList(RulesetDto rulesetDto) {
		// TODO Auto-generated method stub
		return null;
	}

	public boolean shouldBlock() {
		// TODO Auto-generated method stub
		return false;
	}

}
