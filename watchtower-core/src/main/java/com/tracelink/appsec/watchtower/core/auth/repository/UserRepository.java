package com.tracelink.appsec.watchtower.core.auth.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;

/**
 * Repository JPA for the user entities
 *
 * @author csmith
 */
@Repository(value = "userRepository")
public interface UserRepository extends JpaRepository<UserEntity, Long> {

	/**
	 * Get a user by its SSO id, or null if not found.
	 *
	 * @param ssoId the id of the user from the configured SSO
	 * @return a user with the given SSO id, or null
	 */
	UserEntity findBySsoId(String ssoId);

	/**
	 * Get a User by its username, or null if not found
	 *
	 * @param username the username of the user
	 * @return a user with the given username, or null if not found
	 */
	UserEntity findByUsername(String username);

	/**
	 * How many users hold each role, for the Roles page. Roles nobody holds are absent.
	 *
	 * @return one row per role that has at least one user
	 */
	@Query("select r.id as roleId, count(u) as users from UserEntity u join u.roles r group by r.id")
	List<RoleUserCount> countUsersByRole();

	/**
	 * One row of {@link #countUsersByRole()}.
	 */
	interface RoleUserCount {
		long getRoleId();

		long getUsers();
	}
}
