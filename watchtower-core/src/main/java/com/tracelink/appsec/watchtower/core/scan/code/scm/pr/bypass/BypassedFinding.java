package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.util.Objects;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

/**
 * A finding a bypass covers, identified by rule and repo-relative file. A blocking finding of
 * another rule, or in another file, is not covered.
 *
 * @author Watchtower
 */
@Embeddable
public class BypassedFinding {

	@Column(name = "rule_name", nullable = false)
	private String ruleName;

	@Column(name = "file_path", nullable = false, length = 1024)
	private String filePath;

	protected BypassedFinding() {
		// for JPA
	}

	public BypassedFinding(String ruleName, String filePath) {
		this.ruleName = ruleName;
		this.filePath = filePath;
	}

	public String getRuleName() {
		return ruleName;
	}

	public String getFilePath() {
		return filePath;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof BypassedFinding other)) {
			return false;
		}
		return Objects.equals(ruleName, other.ruleName)
				&& Objects.equals(filePath, other.filePath);
	}

	@Override
	public int hashCode() {
		return Objects.hash(ruleName, filePath);
	}
}
