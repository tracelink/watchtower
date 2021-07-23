package com.tracelink.appsec.module.json.model;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;

import com.jayway.jsonpath.JsonPath;
import com.tracelink.appsec.module.json.JsonModule;
import com.tracelink.appsec.watchtower.core.rule.CustomRuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;

/**
 * Represents a data transfer object for the {@link JsonRuleEntity}. All fields in this object are
 * in plain text. Contains JSON-specific fields and inherits fields from the {@link RuleDto}.
 *
 * @author csmith
 */
public class JsonRuleDto extends CustomRuleDto {

	@NotNull(message = "File extension" + CANNOT_BE_NULL)
	private String fileExtension;

	@NotNull(message = "Query" + CANNOT_BE_NULL)
	@NotEmpty(message = "Query" + CANNOT_BE_EMPTY)
	private String query;

	private JsonPath compiledQuery;

	public String getFileExtension() {
		return fileExtension;
	}

	public void setFileExtension(String fileExtension) {
		this.fileExtension = fileExtension;
	}

	public String getQuery() {
		return query;
	}

	public void setQuery(String query) {
		this.query = query;
	}

	public JsonPath getCompiledQuery() {
		if (compiledQuery == null) {
			compiledQuery = JsonPath.compile(query);
		}
		return compiledQuery;
	}

	@Override
	public String getModule() {
		return JsonModule.SCANNER_NAME;
	}

	@Override
	public JsonRuleEntity toEntity() {
		JsonRuleEntity entity = new JsonRuleEntity();
		entity.setExternalUrl(getExternalUrl());
		entity.setFileExtension(getFileExtension());
		entity.setMessage(getMessage());
		entity.setName(getName());
		entity.setPriority(getPriority());
		entity.setQuery(getQuery());
		return entity;
	}

	public boolean isValidExtension(String fileName) {
		return fileExtension.isEmpty() || fileName.endsWith(fileExtension);
	}


}
