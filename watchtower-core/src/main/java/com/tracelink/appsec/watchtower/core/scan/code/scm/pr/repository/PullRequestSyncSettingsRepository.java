package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestSyncSettingsEntity;

/**
 * Repository JPA for the singleton {@link PullRequestSyncSettingsEntity} row.
 */
@Repository(value = "prSyncSettingsRepository")
public interface PullRequestSyncSettingsRepository
		extends JpaRepository<PullRequestSyncSettingsEntity, Long> {
}
