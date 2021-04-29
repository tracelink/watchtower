package com.tracelink.appsec.watchtower.core.rule;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository JPA for the rule entities.
 *
 * @author mcool
 */
@Repository
public interface RuleRepository extends JpaRepository<RuleEntity, Long> {
    RuleEntity findByName(String name);
}
