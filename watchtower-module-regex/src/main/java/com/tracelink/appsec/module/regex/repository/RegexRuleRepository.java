package com.tracelink.appsec.module.regex.repository;


import com.tracelink.appsec.module.regex.model.RegexRuleEntity;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository JPA for the Regex rule entities.
 *
 * @author mcool
 */
@Repository
public interface RegexRuleRepository extends JpaRepository<RegexRuleEntity, Long> {
	RegexRuleEntity findByName(String name);
}
