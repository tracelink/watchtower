package com.tracelink.appsec.watchtower.core.rule;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

/** Stored execution evidence, with no foreign key to a mutable/deletable rule definition. */
@Embeddable
public class RuleIdentityMetadata {
	@Column(name = "execution_rule_id")
	private Long ruleId;
	@Column(name = "rule_module", length = 64)
	private String module;
	@Column(name = "rule_revision", length = 64)
	private String revision;
	@Column(name = "external_rule_key", length = 255)
	private String externalRuleKey;
	@Column(name = "rule_origin_key", length = 255)
	private String originKey;

	public RuleIdentityMetadata() { }

	public RuleIdentityMetadata(RuleExecutionIdentity identity) {
		if (identity != null) {
			ruleId = identity.ruleId();
			module = identity.module();
			revision = identity.revision();
			externalRuleKey = identity.externalRuleKey();
			originKey = identity.originKey();
		}
	}

	public Long getRuleId() { return ruleId; }
	public String getRevision() { return revision; }

	public RuleExecutionIdentity toIdentity() {
		return module == null ? null
				: new RuleExecutionIdentity(ruleId, module, revision, externalRuleKey, originKey);
	}
}
