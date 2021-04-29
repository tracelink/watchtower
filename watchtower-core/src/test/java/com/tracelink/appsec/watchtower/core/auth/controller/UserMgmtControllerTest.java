package com.tracelink.appsec.watchtower.core.auth.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.RoleService;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class UserMgmtControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockBean
	UserService mockUserService;

	@MockBean
	RoleService mockRoleService;

	///////////////////
	// Get usermgmt
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_VIEW_NAME})
	public void testUserList() throws Exception {
		String username = "csmith";
		UserEntity user = createMockUser(username);
		List<UserEntity> userList = new ArrayList<UserEntity>();
		userList.add(user);

		BDDMockito.when(mockUserService.findAllUsers()).thenReturn(userList);
		mockMvc.perform(MockMvcRequestBuilders.get("/usermgmt"))
				.andExpect(
						MockMvcResultMatchers.model().attribute("users", Matchers.contains(user)));
	}

	///////////////////
	// Get usermgmt/edit/{id}
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_VIEW_NAME})
	public void testUserEditViewBadUser() throws Exception {
		BDDMockito.when(mockUserService.findById(BDDMockito.anyInt())).thenReturn(null);
		mockMvc.perform(MockMvcRequestBuilders.get("/usermgmt/edit/123"))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot find user")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_VIEW_NAME})
	public void testUserEditViewUser() throws Exception {
		String username = "csmith";
		UserEntity user = createMockUser(username);
		RoleEntity role = new RoleEntity();
		BDDMockito.when(mockUserService.findById(BDDMockito.anyLong())).thenReturn(user);
		BDDMockito.when(mockRoleService.findAllRoles()).thenReturn(Arrays.asList(role));
		mockMvc.perform(MockMvcRequestBuilders.get("/usermgmt/edit/123"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(
						MockMvcResultMatchers.model().attribute("roles", Matchers.contains(role)))
				.andExpect(
						MockMvcResultMatchers.content().string(Matchers.containsString(username)));
	}

	///////////////////
	// Post usermgmt/edit
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_MODIFY_NAME})
	public void testUserEditBadUser() throws Exception {
		BDDMockito.when(mockUserService.findById(BDDMockito.anyLong())).thenReturn(null);
		int id = 123;
		long role = 2L;
		int enabled = 1;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/usermgmt/edit").param("id", String.valueOf(id))
						.param("role", String.valueOf(role))
						.param("enabled", String.valueOf(enabled))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot find user")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_MODIFY_NAME})
	public void testUserEditCurrentUser() throws Exception {
		UserEntity user = createMockUser(getContextPrincipalName());
		BDDMockito.when(mockUserService.findById(BDDMockito.anyLong())).thenReturn(user);
		int id = 123;
		long role = 2L;
		int enabled = 1;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/usermgmt/edit").param("id", String.valueOf(id))
						.param("role", String.valueOf(role))
						.param("enabled", String.valueOf(enabled))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot edit own information")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_MODIFY_NAME})
	public void testUserEditInvalidState() throws Exception {
		UserEntity user = createMockUser("csmith");
		BDDMockito.when(mockUserService.findById(BDDMockito.anyLong())).thenReturn(user);
		int id = 123;
		long role = 2L;
		int enabled = 2;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/usermgmt/edit").param("id", String.valueOf(id))
						.param("role", String.valueOf(role))
						.param("enabled", String.valueOf(enabled))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Wrong value received for enabled")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_MODIFY_NAME})
	public void testUserEditInvalidRole() throws Exception {
		UserEntity user = createMockUser("csmith");
		BDDMockito.when(mockUserService.findById(BDDMockito.anyLong())).thenReturn(user);
		int id = 123;
		long role = 2L;;
		int enabled = 1;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/usermgmt/edit").param("id", String.valueOf(id))
						.param("role", String.valueOf(role))
						.param("enabled", String.valueOf(enabled))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Unknown role selected")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_MODIFY_NAME})
	public void testUserEditSuccess() throws Exception {
		String username = "csmith";
		UserEntity user = createMockUser(username);
		BDDMockito.when(mockUserService.findById(BDDMockito.anyLong())).thenReturn(user);
		Set<RoleEntity> roles = new HashSet<RoleEntity>();
		RoleEntity adminRole = BDDMockito.mock(RoleEntity.class);

		BDDMockito.when(user.getRoles()).thenReturn(roles);
		BDDMockito.when(mockRoleService.findRoleById(BDDMockito.anyLong()))
				.thenReturn(adminRole);
		int id = 123;
		long role = 2L;
		int enabled = 1;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/usermgmt/edit").param("id", String.valueOf(id))
						.param("role", String.valueOf(role))
						.param("enabled", String.valueOf(enabled))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString(
								"User information for " + username + " saved successfully")));

		MatcherAssert.assertThat(roles, Matchers.contains(adminRole));
	}

	///////////////////
	// Post usermgmt/delete
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_MODIFY_NAME})
	public void testUserEditDeleteBadUser() throws Exception {
		BDDMockito.when(mockUserService.findById(BDDMockito.anyLong())).thenReturn(null);
		int id = 123;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/usermgmt/delete").param("id", String.valueOf(id))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot delete user")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_MODIFY_NAME})
	public void testUserEditDeleteCurrentUser() throws Exception {
		UserEntity user = createMockUser(getContextPrincipalName());
		BDDMockito.when(mockUserService.findById(BDDMockito.anyLong())).thenReturn(user);
		int id = 123;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/usermgmt/delete").param("id", String.valueOf(id))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot delete own account")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_MODIFY_NAME})
	public void testUserEditDeleteUserSuccess() throws Exception {
		UserEntity user = createMockUser("csmith");
		BDDMockito.when(mockUserService.findById(BDDMockito.anyLong())).thenReturn(user);
		int id = 123;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/usermgmt/delete").param("id", String.valueOf(id))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.SUCCESS_NOTIFICATION,
								Matchers.containsString("deleted successfully")));
	}

	private UserEntity createMockUser(String username) {
		UserEntity user = BDDMockito.mock(UserEntity.class);
		BDDMockito.when(user.getUsername()).thenReturn(username);
		return user;
	}

	private String getContextPrincipalName() {
		org.springframework.security.core.userdetails.User principal =
				(org.springframework.security.core.userdetails.User) SecurityContextHolder
						.getContext().getAuthentication().getPrincipal();
		return principal.getUsername();
	}

}
