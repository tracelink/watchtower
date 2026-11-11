package com.tracelink.appsec.watchtower.core.rule.knowledge;

import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface KnowledgeRepository extends JpaRepository<KnowledgeEntity,String> {
 List<KnowledgeEntity> findByStatusOrderByProposedAtDesc(String status,Pageable page);
 List<KnowledgeEntity> findByStatusAndLanguageIgnoreCaseOrderByProposedAtDesc(String status,String language,Pageable page);
}
