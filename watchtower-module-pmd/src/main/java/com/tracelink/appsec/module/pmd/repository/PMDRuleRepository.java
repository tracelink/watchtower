package com.tracelink.appsec.module.pmd.repository;


import com.tracelink.appsec.module.pmd.model.PMDRuleEntity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository JPA for the PMD rule entities.
 *
 * @author mcool
 */
@Repository
public interface PMDRuleRepository extends JpaRepository<PMDRuleEntity, Long> {
	PMDRuleEntity findByName(String name);
}
