package com.tracelink.appsec.module.betterleaks.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleVersionEntity;

/**
 * Repository of custom Betterleaks rule versions.
 *
 * @author Watchtower
 */
public interface BetterleaksRuleVersionRepository
		extends JpaRepository<BetterleaksRuleVersionEntity, Long> {

	/**
	 * @param ruleId the rule
	 * @return its saved versions
	 */
	List<BetterleaksRuleVersionEntity> findByRuleId(long ruleId);
}
