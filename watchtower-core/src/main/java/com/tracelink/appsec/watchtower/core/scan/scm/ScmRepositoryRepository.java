package com.tracelink.appsec.watchtower.core.scan.scm;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository JPA for the SCM repository entities
 *
 * @author csmith
 */
@Repository(value = "repoRepository")
public interface ScmRepositoryRepository extends JpaRepository<ScmRepositoryEntity, Long> {

	ScmRepositoryEntity findByApiLabelAndRepoName(String apiLabel, String repoName);
}
