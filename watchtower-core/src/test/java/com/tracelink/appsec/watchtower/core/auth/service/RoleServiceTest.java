package com.tracelink.appsec.watchtower.core.auth.service;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.repository.RoleRepository;

@ExtendWith(SpringExtension.class)
public class RoleServiceTest {
	private RoleService roleService;

	@MockBean
	private RoleRepository mockRoleRepository;

	

	@BeforeEach
	public void setup() {
		this.roleService = new RoleService(mockRoleRepository);
	}

	@Test
	public void testUnassignDefaultRoles() {
		RoleEntity role = new RoleEntity().setDefaultRole(true);
		BDDMockito.when(mockRoleRepository.findByDefaultRoleTrue()).thenReturn(role);
		roleService.unassignDefaultRoles();
		MatcherAssert.assertThat(role.isDefaultRole(), Matchers.is(false));
	}

	@Test
	public void testAssignDefaultRole() {
		RoleEntity role = new RoleEntity();
		roleService.assignDefaultRole(role);
		BDDMockito.verify(mockRoleRepository).findByDefaultRoleTrue();
		BDDMockito.verify(mockRoleRepository).saveAndFlush(role);
	}

	@Test
	public void testFindDefaultRole() {
		roleService.findDefaultRole();
		BDDMockito.verify(mockRoleRepository).findByDefaultRoleTrue();
	}

	@Test
	public void testFindAllRoles() {
		roleService.findAllRoles();
		BDDMockito.verify(mockRoleRepository).findAll();
	}

	@Test
	public void testFindRoleByName() {
		roleService.findRoleByName("");
		BDDMockito.verify(mockRoleRepository).findByRoleName("");
	}

	@Test
	public void testFindRoleById() {
		roleService.findRoleById(1L);
		BDDMockito.verify(mockRoleRepository).findById(1L);
	}

	@Test
	public void testUpsertRole() {
		RoleEntity role = new RoleEntity();
		roleService.upsertRole(role);
		BDDMockito.verify(mockRoleRepository).saveAndFlush(role);
	}

	@Test
	public void testUpsertRoleUpdate() {
		RoleEntity role = new RoleEntity().setRoleName("name");
		RoleEntity old = new RoleEntity().setId(1L);
		BDDMockito.when(mockRoleRepository.findByRoleName(BDDMockito.anyString())).thenReturn(old);
		roleService.upsertRole(role);
		BDDMockito.verify(mockRoleRepository).saveAndFlush(role);
		MatcherAssert.assertThat(role.getId(), Matchers.is(old.getId()));
	}

	@Test
	public void testSaveRole() {
		RoleEntity role = new RoleEntity();
		roleService.saveRole(role);
		BDDMockito.verify(mockRoleRepository).saveAndFlush(role);
	}

	@Test
	public void testDeleteRole() {
		RoleEntity role = new RoleEntity();
		roleService.deleteRole(role);
		BDDMockito.verify(mockRoleRepository).delete(role);
	}

	@Test
	public void testIsBuiltInRole() {
		RoleEntity role = new RoleEntity().setRoleName("foo");
		Assertions.assertFalse(roleService.isBuiltInRole(role));
		role.setRoleName(RoleService.DEFAULT_ADMIN_ROLE);
		Assertions.assertTrue(roleService.isBuiltInRole(role));
	}
}
