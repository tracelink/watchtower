package com.tracelink.appsec.watchtower.core.ruleset;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * The fingerprint of a module's provided rules at their last import (see
 * {@link ProvidedRulesFingerprint}).
 *
 * @author Watchtower
 */
@Entity
@Table(name = "provided_rules_state")
public class ProvidedRulesStateEntity {

	@Id
	@Column(name = "module_name", nullable = false)
	private String moduleName;

	@Column(name = "fingerprint", nullable = false, length = 64)
	private String fingerprint;

	@Column(name = "imported_at", nullable = false)
	private long importedAt;

	protected ProvidedRulesStateEntity() {
	}

	public ProvidedRulesStateEntity(String moduleName, String fingerprint, long importedAt) {
		this.moduleName = moduleName;
		this.fingerprint = fingerprint;
		this.importedAt = importedAt;
	}

	public String getModuleName() {
		return moduleName;
	}

	public String getFingerprint() {
		return fingerprint;
	}

	public long getImportedAt() {
		return importedAt;
	}
}
