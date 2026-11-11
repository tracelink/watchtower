package com.tracelink.appsec.watchtower.core.scan.code;


import com.fasterxml.jackson.annotation.JsonIgnore;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;

/** Only hashes/configuration identifiers, never environment variables, credentials or paths. */
public record EngineExecutionIdentity(String engine, String version, String configurationHash,
		boolean configurationComplete) {

	@JsonIgnore
	public boolean isReusable() {
		return configurationComplete && engine != null && !engine.isBlank()
				&& version != null && !version.isBlank()
				&& configurationHash != null && configurationHash.matches("[0-9a-f]{64}");
	}

	public String fingerprint() {
		return RuleRevision.definition("engine-execution", "v1").field("engine", engine)
				.field("version", version).field("configurationHash", configurationHash)
				.field("complete", Boolean.toString(configurationComplete)).hash();
	}

	public static EngineExecutionIdentity unknown(String engine) {
		return new EngineExecutionIdentity(engine, null, null, false);
	}

}
