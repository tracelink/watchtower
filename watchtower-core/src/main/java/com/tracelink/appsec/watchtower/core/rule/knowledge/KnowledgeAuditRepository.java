package com.tracelink.appsec.watchtower.core.rule.knowledge;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface KnowledgeAuditRepository extends JpaRepository<KnowledgeAuditEntity,Long> {
 List<KnowledgeAuditEntity> findByKnowledgeIdOrderByAuditIdAsc(String knowledgeId);
}
