package com.tracelink.appsec.module.advisory.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.module.advisory.model.AdvisoryRuleEntity;

@Repository
public interface AdvisoryRuleRepository extends JpaRepository<AdvisoryRuleEntity, Long> {

	AdvisoryRuleEntity findByName(String name);
}
