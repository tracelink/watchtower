package com.tracelink.appsec.watchtower.core.auth.model;

import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class UserTest {

	@Test
	public void testDAO() {
		Date created = new Date();
		int enabled = 1;
		Date lastLogin = new Date();
		Date lastModified = new Date();
		String password = "foobar";
		String username = "csmith";
		Set<RoleEntity> roles = new HashSet<RoleEntity>();
		RoleEntity role = new RoleEntity();
		String role1Name = "role1";
		role.setRoleName(role1Name);
		roles.add(role);
		RoleEntity role2 = new RoleEntity();
		String role2Name = "role2";
		role2.setRoleName(role2Name);
		roles.add(role2);

		UserEntity user = new UserEntity();
		user.setCreated(created);
		user.setEnabled(enabled);
		user.setLastLogin(lastLogin);
		user.setLastModified(lastModified);
		user.setPassword(password);
		user.setPasswordConfirmation(password);
		user.setUsername(username);
		user.setRoles(roles);

		Assertions.assertEquals(username, user.getUsername());
		Assertions.assertEquals(enabled, user.getEnabled());
		Assertions.assertEquals(password, user.getPassword());
		Assertions.assertEquals(password, user.getPasswordConfirmation());
		Assertions.assertEquals(2, user.getRoles().size());
		Assertions.assertTrue(user.getRoles().contains(role));
		Assertions.assertTrue(user.getRoles().contains(role2));
		Assertions.assertTrue(user.getRolesString().contains(","));
		Assertions.assertTrue(user.getRolesString().contains(role1Name));
		Assertions.assertTrue(user.getRolesString().contains(role2Name));
		Assertions.assertEquals(lastLogin, user.getLastLogin());
		Assertions.assertEquals(lastModified, user.getLastModified());
		Assertions.assertEquals(created, user.getCreated());
	}

}
