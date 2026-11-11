package com.tracelink.appsec.watchtower.core.ruleset;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repository of each module's provided-rules fingerprint, keyed by module name.
 *
 * @author Watchtower
 */
public interface ProvidedRulesStateRepository
		extends JpaRepository<ProvidedRulesStateEntity, String> {
}
