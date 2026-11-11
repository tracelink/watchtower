package com.tracelink.appsec.module.betterleaks.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleEntity;

/**
 * Repository of Betterleaks rules.
 *
 * @author Watchtower
 */
public interface BetterleaksRuleRepository extends JpaRepository<BetterleaksRuleEntity, Long> {
}
