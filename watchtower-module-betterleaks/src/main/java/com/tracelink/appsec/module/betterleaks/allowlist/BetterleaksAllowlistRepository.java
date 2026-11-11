package com.tracelink.appsec.module.betterleaks.allowlist;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Repository of Betterleaks allowlist entries.
 *
 * @author Watchtower
 */
public interface BetterleaksAllowlistRepository
		extends JpaRepository<BetterleaksAllowlistEntryEntity, Long> {
}
