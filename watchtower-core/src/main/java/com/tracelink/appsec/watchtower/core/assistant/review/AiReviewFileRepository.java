package com.tracelink.appsec.watchtower.core.assistant.review;

import java.util.Collection;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

public interface AiReviewFileRepository extends JpaRepository<AiReviewFileEntity, String> {
	List<AiReviewFileEntity> findByRunIdOrderByPath(String runId);

	void deleteByRunIdIn(Collection<String> runIds);
}
