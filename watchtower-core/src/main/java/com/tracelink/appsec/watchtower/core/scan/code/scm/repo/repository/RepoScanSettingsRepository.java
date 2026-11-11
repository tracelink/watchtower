package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanSettingsEntity;

/**
 * The single row of repository scan settings.
 *
 * @author Watchtower
 */
@Repository
public interface RepoScanSettingsRepository extends JpaRepository<RepoScanSettingsEntity, Long> {
}
