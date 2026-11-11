package com.tracelink.appsec.watchtower.core.rule;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RuleStewardshipHistoryRepository extends JpaRepository<RuleStewardshipHistoryEntity, Long> {
}
