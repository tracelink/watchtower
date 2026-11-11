package com.tracelink.appsec.watchtower.core.assistant.review;

import java.util.Collection;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AiReviewRunRepository extends JpaRepository<AiReviewRunEntity, String> {
	List<AiReviewRunEntity> findTop5ByScanTypeAndScanIdOrderByCreatedAtDesc(String scanType, long scanId);

	long countByRequestedByAndStatusIn(String requestedBy, Collection<String> statuses);

	List<AiReviewRunEntity> findByExpiresAtLessThan(long now);
}
