package com.tracelink.appsec.watchtower.core.assistant.review;

import java.util.Collection;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AiReviewItemRepository extends JpaRepository<AiReviewItemEntity, String> {
	List<AiReviewItemEntity> findByRunIdOrderByPathAscFirstLineAsc(String runId);

	void deleteByRunIdIn(Collection<String> runIds);
}
