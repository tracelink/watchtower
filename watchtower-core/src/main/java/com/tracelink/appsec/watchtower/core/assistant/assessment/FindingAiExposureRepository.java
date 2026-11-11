package com.tracelink.appsec.watchtower.core.assistant.assessment;

import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingAiExposureRepository extends JpaRepository<FindingAiExposureEntity,FindingAiExposureEntity.Key> {
 List<FindingAiExposureEntity> findByOccurrenceKeyIn(Collection<String> occurrenceKeys);
}
