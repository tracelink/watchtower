package com.tracelink.appsec.module.checkov.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.tracelink.appsec.module.checkov.model.CheckovRuleEntity;

/**
 * Repository definition of a Checkov Rule
 * 
 * @author csmith
 *
 */
public interface CheckovRuleRepository extends JpaRepository<CheckovRuleEntity, Long> {

}
