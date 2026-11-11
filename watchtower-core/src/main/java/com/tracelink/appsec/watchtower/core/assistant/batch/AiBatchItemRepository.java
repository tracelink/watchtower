package com.tracelink.appsec.watchtower.core.assistant.batch;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AiBatchItemRepository extends JpaRepository<AiBatchItemEntity,AiBatchItemEntity.Key> {
 List<AiBatchItemEntity> findByRunIdOrderByFindingKey(String runId);
}
