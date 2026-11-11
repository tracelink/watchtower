package com.tracelink.appsec.watchtower.core.assistant.assessment;

import java.util.List;
import java.util.Optional;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingAssessmentRepository extends JpaRepository<FindingAssessmentEntity,String> {
 Optional<FindingAssessmentEntity> findByOccurrenceKeyAndModelAndEffortAndPromptVersion(String occurrenceKey,String model,String effort,String promptVersion);
 Optional<FindingAssessmentEntity> findFirstByOccurrenceKeyOrderByCreatedAtDesc(String occurrenceKey);
 List<FindingAssessmentEntity> findByStatusOrderByCreatedAtDesc(String status,Pageable page);
}
