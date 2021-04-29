package com.tracelink.appsec.watchtower.core.auth.model;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class RoleTest {

	@Test
	public void testDAO() {
		String roleName = "foobar";
		String description = "desc";
		boolean defaultRole = true;
		PrivilegeEntity priv = new PrivilegeEntity();

		RoleEntity role = new RoleEntity();
		role.setRoleName(roleName);
		role.setDescription(description);
		role.setDefaultRole(defaultRole);
		role.getPrivileges().add(priv);

		Assertions.assertEquals(roleName, role.getRoleName());
		Assertions.assertEquals(description, role.getDescription());
		Assertions.assertEquals(defaultRole, role.isDefaultRole());
		MatcherAssert.assertThat(role.getPrivileges(), Matchers.contains(priv));
	}

}
