package com.tracelink.appsec.watchtower.core.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;

/**
 * Repository for Privileges
 * 
 * @author csmith
 *
 */
@Repository
public interface PrivilegesRepository extends JpaRepository<PrivilegeEntity, Long> {

	PrivilegeEntity findByName(String name);
}
