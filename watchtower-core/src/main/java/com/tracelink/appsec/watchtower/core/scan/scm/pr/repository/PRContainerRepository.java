package com.tracelink.appsec.watchtower.core.scan.scm.pr.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.IContainerRepository;
import com.tracelink.appsec.watchtower.core.scan.scm.pr.entity.PullRequestContainerEntity;

/**
 * Repository JPA for the pull request entities
 * 
 * @author csmith
 *
 */
@Repository(value = "prContainerRepository")
public interface PRContainerRepository
		extends IContainerRepository<PullRequestContainerEntity> {

	PullRequestContainerEntity findOneByApiLabelAndRepoNameAndPrId(String apiLabel,
			String repoName, String prId);

	Page<PullRequestContainerEntity> findByResolvedFalse(Pageable pageable);
}
