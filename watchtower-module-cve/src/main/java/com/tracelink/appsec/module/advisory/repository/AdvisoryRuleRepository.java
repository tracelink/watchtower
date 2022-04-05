package com.tracelink.appsec.module.advisory.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tracelink.appsec.module.advisory.model.AdvisoryRuleEntity;

public interface AdvisoryRuleRepository extends JpaRepository<AdvisoryRuleEntity, Long> {

}
