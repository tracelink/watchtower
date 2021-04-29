package com.tracelink.appsec.module.eslint.engine.json;

import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import java.util.stream.Collectors;

/**
 * JSON model for an ESLint rule. Contains two fields, a {@link Meta} object containing metadata and
 * a String containing the contents of the create function for the rule.
 *
 * @author mcool
 */
public class EsLintRuleJsonModel {

	private Meta meta;

	private String createFunction;

	public Meta getMeta() {
		return meta;
	}

	public void setMeta(Meta meta) {
		this.meta = meta;
	}

	public String getCreateFunction() {
		return createFunction;
	}

	public void setCreateFunction(String createFunction) {
		this.createFunction = createFunction;
	}

	/**
	 * Converts this JSON model into an ESLint rule data transfer object. Used for ESLint ruleset
	 * import.
	 *
	 * @return rule DTO representing this ESLint JSON model
	 */
	public RuleDto toDto() {
		EsLintRuleDto rule = new EsLintRuleDto();
		rule.setType(meta.getType());
		if (meta.getDocs() != null) {
			Docs docs = meta.getDocs();
			rule.setMessage(docs.getDescription());
			rule.setCategory(docs.getCategory());
			rule.setRecommended(docs.getRecommended());
			rule.setExternalUrl(docs.getUrl());
			rule.setSuggestion(docs.getSuggestion());
		}
		rule.setFixable(meta.getFixable());
		rule.setSchema(meta.getSchema());
		rule.setDeprecated(meta.getDeprecated());
		rule.setReplacedBy(meta.getReplacedBy());
		rule.setMessages(meta.getMessages().entrySet().stream().map(e -> {
			EsLintMessageDto message = new EsLintMessageDto();
			message.setKey(e.getKey());
			message.setValue(e.getValue());
			return message;
		}).collect(Collectors.toList()));
		rule.setCreateFunction(createFunction);
		return rule;
	}
}
