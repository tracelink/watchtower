package com.tracelink.appsec.module.pmd.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

public interface PMDRuleDto {
	@JsonIgnore
	boolean isProvided();
}
