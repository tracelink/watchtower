package com.tracelink.appsec.watchtower.core.ruleset;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository JPA for the ruleset entities.
 *
 * @author mcool
 */
@Repository
public interface RulesetRepository extends JpaRepository<RulesetEntity, Long> {
    RulesetEntity findByName(String name);

    RulesetEntity findByDesignation(RulesetDesignation designation);
}
