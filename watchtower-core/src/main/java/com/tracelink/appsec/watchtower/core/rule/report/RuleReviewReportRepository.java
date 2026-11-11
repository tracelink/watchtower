package com.tracelink.appsec.watchtower.core.rule.report;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RuleReviewReportRepository extends JpaRepository<RuleReviewReportEntity,String> {
 boolean existsByPeriodKey(String periodKey);
 Optional<RuleReviewReportEntity> findFirstByOrderByCreatedAtDesc();
}
