package com.tracelink.appsec.watchtower.core.auth.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.service.PrivilegeService;
import com.tracelink.appsec.watchtower.core.auth.service.RoleService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class RoleMgmtControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	private RoleService mockRoleService;

	@MockitoBean
	private PrivilegeService mockPrivilegeService;


	///////////////////
	// Get rolemgmt
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_VIEW_NAME})
	public void testRoleMgmt() throws Exception {
		String roleName = "myrole";
		RoleEntity role = new RoleEntity().setRoleName(roleName);
		List<RoleEntity> roleList = new ArrayList<RoleEntity>();
		roleList.add(role);
		BDDMockito.when(mockRoleService.findDefaultRole()).thenReturn(role);
		BDDMockito.when(mockRoleService.findAllRoles()).thenReturn(roleList);
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/rolemgmt"))
				.andExpect(
						MockMvcResultMatchers.model().attribute("roles", Matchers.contains(role)))
				.andExpect(
						MockMvcResultMatchers.model().attribute("defaultRole",
								Matchers.is(role)))
				.andReturn();
		// admin/rolemgmt.html had the form-inline, close-button and selectpicker (default-role
		// select) conversions in Phase 11 Section B - guard the result structurally.
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_VIEW_NAME, CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtShowsDefaultAsInUseAndOthersAsDeletable() throws Exception {
		RoleEntity defaultRole = new RoleEntity().setRoleName("Default User").setDefaultRole(true);
		RoleEntity other = new RoleEntity().setRoleName("Auditors");
		BDDMockito.when(mockRoleService.findAllRoles()).thenReturn(List.of(defaultRole, other));
		BDDMockito.when(mockPrivilegeService.getAllPrivileges()).thenReturn(List.of());

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/rolemgmt"))
				.andExpect(MockMvcResultMatchers.model().attributeExists("roleUsers"))
				.andExpect(MockMvcResultMatchers.model().attribute("privilegeTotal", 0))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
		String html = result.getResponse().getContentAsString();
		Assertions.assertTrue(html.contains("In use"));
		Assertions.assertTrue(html.contains("aria-label=\"Delete Auditors\""));
		Assertions.assertFalse(html.contains("aria-label=\"Delete Default User\""));
		Assertions.assertTrue(html.contains("Make Auditors the default role"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtDeleteDefaultRoleRefused() throws Exception {
		RoleEntity role = new RoleEntity().setRoleName("Default User").setDefaultRole(true);
		BDDMockito.when(mockRoleService.findRoleById(BDDMockito.anyLong())).thenReturn(role);
		mockMvc.perform(MockMvcRequestBuilders.post("/rolemgmt/delete").param("id", "5")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Make another role the default first")));
		BDDMockito.verify(mockRoleService, BDDMockito.never()).deleteRole(role);
	}

	///////////////////
	// Get rolemgmt/edit/{id}
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_VIEW_NAME})
	public void testRoleMgmtViewBadRole() throws Exception {
		BDDMockito.when(mockRoleService.findRoleById(BDDMockito.anyInt())).thenReturn(null);
		mockMvc.perform(MockMvcRequestBuilders.get("/rolemgmt/edit/123"))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot find role")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_VIEW_NAME})
	public void testRoleMgmtViewRole() throws Exception {
		String roleName = "roleName";
		RoleEntity role = new RoleEntity().setRoleName(roleName);
		PrivilegeEntity priv = new PrivilegeEntity();
		BDDMockito.when(mockRoleService.findRoleById(BDDMockito.anyLong())).thenReturn(role);
		BDDMockito.when(mockPrivilegeService.getAllPrivileges()).thenReturn(Arrays.asList(priv));
		mockMvc.perform(MockMvcRequestBuilders.get("/rolemgmt/edit/123"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(
						MockMvcResultMatchers.model().attribute("role", Matchers.is(role)))
				.andExpect(
						MockMvcResultMatchers.model().attribute("privileges",
								Matchers.contains(priv)))
				.andExpect(MockMvcResultMatchers.model().attribute("privilegesByModule",
						Matchers.instanceOf(java.util.Map.class)));
	}

	///////////////////
	// Post rolemgmt/edit
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtBadRole() throws Exception {
		BDDMockito.when(mockRoleService.findRoleById(BDDMockito.anyLong())).thenReturn(null);
		int id = 123;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/edit").param("id", String.valueOf(id))
						.param("PrivName", String.valueOf(true))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot find role")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtBuiltInRole() throws Exception {
		RoleEntity role = new RoleEntity().setRoleName("roleName");
		BDDMockito.when(mockRoleService.findRoleById(BDDMockito.anyLong())).thenReturn(role);
		BDDMockito.when(mockRoleService.isBuiltInRole(role)).thenReturn(true);
		int id = 123;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/edit").param("id", String.valueOf(id))
						.param("PrivName", String.valueOf(true))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot edit a built in role")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtSuccess() throws Exception {
		String roleName = "roleName";
		RoleEntity role = new RoleEntity().setRoleName(roleName);
		BDDMockito.when(mockRoleService.findRoleById(BDDMockito.anyLong())).thenReturn(role);

		String privName = "PrivName";
		PrivilegeEntity priv = new PrivilegeEntity();
		priv.setName(privName);
		BDDMockito.when(mockPrivilegeService.findByName(privName)).thenReturn(priv);

		int id = 123;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/edit").param("id", String.valueOf(id))
						.param(privName, String.valueOf(true))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString(
								"Role information for " + roleName + " saved successfully")));

		MatcherAssert.assertThat(role.getPrivileges(), Matchers.contains(priv));
	}

	///////////////////
	// Post rolemgmt/delete
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtDeleteBadRole() throws Exception {
		BDDMockito.when(mockRoleService.findRoleById(BDDMockito.anyLong())).thenReturn(null);
		int id = 123;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/delete").param("id", String.valueOf(id))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot delete role")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtDeleteBuiltInRole() throws Exception {
		RoleEntity role = new RoleEntity();
		BDDMockito.when(mockRoleService.findRoleById(BDDMockito.anyLong())).thenReturn(role);
		BDDMockito.when(mockRoleService.isBuiltInRole(role)).thenReturn(true);
		int id = 123;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/delete").param("id", String.valueOf(id))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot delete a built in role")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtDeleteRoleSuccess() throws Exception {
		RoleEntity user = new RoleEntity();
		BDDMockito.when(mockRoleService.findRoleById(BDDMockito.anyLong())).thenReturn(user);
		int id = 123;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/delete").param("id", String.valueOf(id))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								Matchers.containsString("deleted successfully")));
	}

	///////////////////
	// Post rolemgmt/create
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtCreateRoleSuccess() throws Exception {
		long roleId = 1L;
		String roleName = "roleName";
		String roleDescription = "roleDesc";
		BDDMockito.when(mockRoleService.findRoleByName(roleName)).thenReturn(null);
		BDDMockito.when(mockRoleService.upsertRole(BDDMockito.any()))
				.thenReturn(new RoleEntity().setId(roleId));
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/create")
						.param("roleName", roleName)
						.param("roleDescription", roleDescription)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection());
		ArgumentCaptor<RoleEntity> roleCaptor = ArgumentCaptor.forClass(RoleEntity.class);
		BDDMockito.verify(mockRoleService).upsertRole(roleCaptor.capture());
		MatcherAssert.assertThat(roleCaptor.getValue().getRoleName(), Matchers.is(roleName));
		MatcherAssert.assertThat(roleCaptor.getValue().getDescription(), Matchers.is(roleDescription));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtCreateRoleAlreadyExists() throws Exception {
		BDDMockito.when(mockRoleService.findRoleByName(BDDMockito.anyString()))
				.thenReturn(new RoleEntity());
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/create")
						.param("roleName", "r")
						.param("roleDescription", "d")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Role already exists")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtCreateRoleBad() throws Exception {
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/create")
						.param("roleName", "")
						.param("roleDescription", "d")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Role must have a name")));
	}


	///////////////////
	// Post rolemgmt/default
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtDefaultRoleSuccess() throws Exception {
		long roleId = 1L;
		RoleEntity role = new RoleEntity();
		BDDMockito.when(mockRoleService.findRoleById(roleId)).thenReturn(role);
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/default")
						.param("roleId", String.valueOf(roleId))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString("Successfully assigned")));

		ArgumentCaptor<RoleEntity> roleCaptor = ArgumentCaptor.forClass(RoleEntity.class);
		BDDMockito.verify(mockRoleService).assignDefaultRole(roleCaptor.capture());
		MatcherAssert.assertThat(roleCaptor.getValue(), Matchers.is(role));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtDefaultRoleUnknown() throws Exception {
		long roleId = 1L;
		BDDMockito.when(mockRoleService.findRoleById(roleId)).thenReturn(null);
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/default")
						.param("roleId", String.valueOf(roleId))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.FAILURE_NOTIFICATION,
						Matchers.containsString("Cannot assign default role")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.ROLE_MODIFY_NAME})
	public void testRoleMgmtDefaultRoleUnassign() throws Exception {
		long roleId = -1L;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/rolemgmt/default")
						.param("roleId", String.valueOf(roleId))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString("Successfully unassigned")));
	}

}
