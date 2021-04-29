package com.tracelink.appsec.module.json.model;

import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetEntity;
import java.util.stream.Collectors;
import javax.persistence.Column;
import javax.persistence.Convert;
import javax.persistence.Entity;
import javax.persistence.PrimaryKeyJoinColumn;
import javax.persistence.Table;

/**
 * Entity description for an Json rule entity. Contains JSON-specific fields and inherits fields
 * from the {@link RuleEntity}.
 *
 * @author csmith
 */
@Entity
@PrimaryKeyJoinColumn(name = "rule_id")
@Table(name = "json_rules")
public class JsonRuleEntity extends RuleEntity {

	@Column(name = "query")
	@Convert(converter = HexStringConverter.class)
	private String query;

	@Column(name = "file_extension")
	private String fileExtension;

	public String getQuery() {
		return query;
	}

	public void setQuery(String query) {
		this.query = query;
	}

	public String getFileExtension() {
		return fileExtension;
	}

	public void setFileExtension(String fileExtension) {
		this.fileExtension = fileExtension;
	}

	@Override
	public JsonRuleDto toDto() {
		JsonRuleDto rule = new JsonRuleDto();
		rule.setAuthor(getAuthor());
		rule.setExternalUrl(getExternalUrl());
		rule.setFileExtension(getFileExtension());
		rule.setMessage(getMessage());
		rule.setId(getId());
		rule.setName(getName());
		rule.setPriority(getPriority());
		rule.setQuery(getQuery());
		rule.setRulesets(
				getRulesets().stream().map(RulesetEntity::getName).collect(Collectors.toSet()));
		return rule;
	}

}
