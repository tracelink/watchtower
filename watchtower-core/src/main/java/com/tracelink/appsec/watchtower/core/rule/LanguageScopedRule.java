package com.tracelink.appsec.watchtower.core.rule;

import java.util.Set;

/**
 * Implemented by rule DTOs whose definition names the languages it scans (for example a PMD parser
 * language or Opengrep's {@code languages}). Not a bean getter, so rule export JSON is unchanged.
 */
public interface LanguageScopedRule {
	Set<String> scannedLanguages();
}
