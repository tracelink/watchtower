package com.tracelink.appsec.module.json.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.module.json.model.JsonRuleEntity;

/**
 * Repository JPA for the Json rule entities.
 *
 * @author csmith
 */
@Repository
public interface JsonRuleRepository extends JpaRepository<JsonRuleEntity, Long> {

	JsonRuleEntity findByName(String name);

}
