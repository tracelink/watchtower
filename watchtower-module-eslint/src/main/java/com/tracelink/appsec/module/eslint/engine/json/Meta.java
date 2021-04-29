package com.tracelink.appsec.module.eslint.engine.json;

import com.google.gson.JsonParser;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.tracelink.appsec.module.eslint.model.EsLintRuleFixable;
import com.tracelink.appsec.module.eslint.model.EsLintRuleType;
import java.io.IOException;
import java.util.Map;

/**
 * JSON model for the "meta" section of ESLint rules that contains rule metadata.
 *
 * @author mcool
 */
public class Meta {

	private EsLintRuleType type;

	private Docs docs;

	private EsLintRuleFixable fixable;

	@JsonAdapter(RawJsonAdapter.class)
	private String schema;

	private Boolean deprecated;

	@JsonAdapter(RawJsonAdapter.class)
	private String replacedBy;

	private Map<String, String> messages;

	public EsLintRuleType getType() {
		return type;
	}

	public void setType(EsLintRuleType type) {
		this.type = type;
	}

	public Docs getDocs() {
		return docs;
	}

	public void setDocs(Docs docs) {
		this.docs = docs;
	}

	public EsLintRuleFixable getFixable() {
		return fixable;
	}

	public void setFixable(EsLintRuleFixable fixable) {
		this.fixable = fixable;
	}

	public String getSchema() {
		return schema;
	}

	public void setSchema(String schema) {
		this.schema = schema;
	}

	public Boolean getDeprecated() {
		return deprecated;
	}

	public void setDeprecated(Boolean deprecated) {
		this.deprecated = deprecated;
	}

	public String getReplacedBy() {
		return replacedBy;
	}

	public void setReplacedBy(String replacedBy) {
		this.replacedBy = replacedBy;
	}

	public Map<String, String> getMessages() {
		return messages;
	}

	public void setMessages(Map<String, String> messages) {
		this.messages = messages;
	}

	/**
	 * Adapter to store JSON as a String rather than parsing through it.
	 */
	static class RawJsonAdapter extends TypeAdapter<String> {

		@Override
		public void write(JsonWriter out, String value) throws IOException {
			out.jsonValue(value);
		}

		@Override
		public String read(JsonReader in) throws IOException {
			return JsonParser.parseReader(in).toString();
		}
	}
}
