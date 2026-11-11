package com.tracelink.appsec.module.awssecurity;
import java.util.*;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import org.springframework.data.domain.Pageable;
import jakarta.persistence.LockModeType;

public interface AwsSecurityRunRepository extends JpaRepository<AwsSecurityRun, String> {
    @EntityGraph(attributePaths={"nativeSeverityCounts"})
    Optional<AwsSecurityRun> findByExecutionKey(String key);
    List<AwsSecurityRun> findByParentTypeAndParentIdOrderByCreatedAtAsc(String type, long parentId);
    @Lock(LockModeType.PESSIMISTIC_WRITE) @Query("select r from AwsSecurityRun r where r.id = :id")
    Optional<AwsSecurityRun> locked(@Param("id") String id);
    List<AwsSecurityRun> findByDueAtLessThanEqualOrderByCreatedAtAsc(long now, Pageable page);
    boolean existsByParentTypeAndStage(String type, AwsSecurityRun.Stage stage);
    boolean existsByParentTypeAndStageNotIn(String type, Collection<AwsSecurityRun.Stage> stages);
    List<AwsSecurityRun> findByParentTypeOrderByCreatedAtDesc(String type, Pageable page);
    List<AwsSecurityRun> findByParentTypeAndAggregatePublishedFalseOrderByCreatedAtAsc(String type, Pageable page);
    interface Totals {
        AwsSecurityRun.Stage getStage(); long getJobs(); long getInputBytes(); long getImported(); long getMissing(); long getOmitted(); long getFailures(); long getThrottles();
    }
    @Query("select r.stage as stage, count(r) as jobs, sum(r.sourceBytes + r.diffBytes) as inputBytes, sum(r.importedCount) as imported, sum(r.missingCount) as missing, sum(r.omittedCount) as omitted, sum(r.failureCount) as failures, sum(r.throttleCount) as throttles from AwsSecurityRun r group by r.stage")
    List<Totals> operationalTotals();
    interface EvidenceCount { String getLabel(); long getFindings(); }
    @Query("select key(c) as label, sum(value(c)) as findings from AwsSecurityRun r join r.nativeSeverityCounts c where r.parentType <> 'setup' group by key(c)")
    List<EvidenceCount> severityTotals();
    @Query("select key(c) as label, sum(value(c)) as findings from AwsSecurityRun r join r.validationCounts c where r.parentType <> 'setup' group by key(c)")
    List<EvidenceCount> validationTotals();
    @Query("select count(p) from AwsSecurityPermit p where p.runId is not null")
    long activePermitCount();
    /** Whether any repository or pull request scan has used AWS (setup tests do not count). */
    @Query("select count(r) > 0 from AwsSecurityRun r where r.parentType <> 'setup'")
    boolean hasScanRun();
    long countByNeedsReconciliationTrue();
    @Query("select min(r.createdAt) from AwsSecurityRun r where r.cleanupComplete = false and r.sourceKey is not null")
    Optional<Long> oldestInput();
    @Query("select avg(r.terminalAt - r.createdAt) from AwsSecurityRun r where r.terminalAt > r.createdAt")
    Optional<Double> averageLatencyMillis();
}
