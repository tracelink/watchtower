package com.tracelink.appsec.watchtower.core.encryption.model;

/**
 * Enum for different encryption strategies.
 *
 * @author mcool
 */
public enum EncryptionType {
	/*
	 * No encryption configured, any currently encrypted values will be decrypted
	 */
	NONE("none"),
	/*
	 * Encryption configured, current and previous key encryption keys provided via environment
	 * variables
	 */
	ENVIRONMENT("environment");

	EncryptionType(String value) {
	}
}
