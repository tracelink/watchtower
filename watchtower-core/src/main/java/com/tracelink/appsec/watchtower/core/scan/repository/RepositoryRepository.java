package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.ScanType;

/**
 * Repository JPA for the SCM repository entities
 *
 * @author csmith
 */
@Repository(value = "repoRepository")
public interface RepositoryRepository extends JpaRepository<RepositoryEntity, Long> {

	RepositoryEntity findByApiLabelAndRepoName(String apiLabel, String repoName);

	List<RepositoryEntity> findByScanType(ScanType scanType);
}
