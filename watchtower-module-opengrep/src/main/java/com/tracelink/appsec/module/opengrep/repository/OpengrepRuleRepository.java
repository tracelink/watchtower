package com.tracelink.appsec.module.opengrep.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.tracelink.appsec.module.opengrep.model.OpengrepRuleEntity;
public interface OpengrepRuleRepository extends JpaRepository<OpengrepRuleEntity,Long> { }
