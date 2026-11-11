package com.tracelink.appsec.watchtower.core.assistant.batch;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AiBatchRunRepository extends JpaRepository<AiBatchRunEntity,String> {
 Optional<AiBatchRunEntity> findByScanTypeAndScanId(String scanType,long scanId);
}
