package com.tracelink.appsec.module.eslint.repository;

import com.tracelink.appsec.module.eslint.model.EsLintRuleEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository JPA for the ESLint rule entities.
 *
 * @author mcool
 */
@Repository
public interface EsLintRuleRepository extends JpaRepository<EsLintRuleEntity, Long> {

	EsLintRuleEntity findByName(String name);
}
