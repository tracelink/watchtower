package com.tracelink.appsec.module.eslint.model;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.validation.Valid;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;

/**
 * Represents a data transfer object for the {@link EsLintRuleEntity} for custom rules. All fields
 * in this object are in plain text. Contains ESLint-specific fields and inherits fields from the
 * {@link CustomRuleDto}.
 *
 * @author mcool
 */
public class EsLintCustomRuleDto extends CustomRuleDto implements EsLintRuleDto {

	@Valid
	private List<EsLintMessageDto> messages = new ArrayList<>();

	@NotNull(message = "Create Funtion" + CANNOT_BE_NULL)
	@NotEmpty(message = "Create Funtion" + CANNOT_BE_EMPTY)
	private String createFunction;

	private String schema;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getModule() {
		return EsLintModule.MODULE_NAME;
	}

	@Override
	public boolean isCore() {
		return false;
	}

	public List<EsLintMessageDto> getMessages() {
		return messages;
	}

	public void setMessages(List<EsLintMessageDto> messages) {
		this.messages = messages;
	}

	public String getCreateFunction() {
		return createFunction;
	}

	public void setCreateFunction(String createFunction) {
		this.createFunction = createFunction;
	}

	public String getSchema() {
		return schema;
	}

	public void setSchema(String schema) {
		this.schema = schema;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RuleEntity toEntity() {
		EsLintRuleEntity rule = new EsLintRuleEntity();
		// Set inherited fields
		rule.setName(getName());
		rule.setMessage(getMessage());
		rule.setExternalUrl(getExternalUrl());
		rule.setPriority(getPriority());
		// Set ESLint-specific fields
		rule.setCore(isCore());
		rule.setMessages(
				getMessages().stream().map(EsLintMessageDto::toEntity)
						.collect(Collectors.toSet()));
		rule.setCreateFunction(getCreateFunction());
		return rule;
	}
}
