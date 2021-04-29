package com.tracelink.appsec.watchtower.core.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;

/**
 * Repository JPA for the role entities
 *
 * @author csmith
 */
@Repository(value = "roleRepository")
public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
	RoleEntity findByRoleName(String roleName);

	RoleEntity findByDefaultRoleTrue();
}
