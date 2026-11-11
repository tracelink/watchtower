package com.tracelink.appsec.watchtower.core.auth.controller;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.service.RoleService;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;
import com.tracelink.appsec.watchtower.core.auth.service.UserService;
import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class UserMgmtControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	UserService mockUserService;

	@MockitoBean
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
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/usermgmt"))
				.andExpect(
						MockMvcResultMatchers.model().attribute("users", Matchers.contains(user)))
				.andExpect(MockMvcResultMatchers.model().attribute("hasUsers", true))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.not(Matchers.containsString("No users registered"))))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
	}

	@Test
	@WithMockUser(username = "me", authorities = {CorePrivilege.USER_VIEW_NAME,
			CorePrivilege.USER_MODIFY_NAME})
	public void testUserListShowsYouOnOwnRowAndFlagsStaleLogins() throws Exception {
		UserEntity me = createMockUser("me");
		BDDMockito.when(me.getLastLogin()).thenReturn(LocalDateTime.now().minusMinutes(5));
		UserEntity stale = createMockUser("old");
		BDDMockito.when(stale.getId()).thenReturn(7L);
		BDDMockito.when(stale.getLastLogin()).thenReturn(LocalDateTime.now().minusDays(400));
		BDDMockito.when(mockUserService.findAllUsers()).thenReturn(List.of(me, stale));

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/usermgmt"))
				.andExpect(MockMvcResultMatchers.model().attribute("currentUsername", "me"))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
		String html = result.getResponse().getContentAsString();
		Assertions.assertFalse(html.contains("aria-label=\"Delete me\""));
		Assertions.assertTrue(html.contains("aria-label=\"Delete old\""));
		Assertions.assertTrue(html.contains("You can&#39;t delete your own account")
				|| html.contains("You can't delete your own account"));
		Assertions.assertTrue(html.contains("No login for over 90 days"));
		Assertions.assertTrue(html.contains("2 users"));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_VIEW_NAME})
	public void testEmptyUserListShowsEmptyState() throws Exception {
		BDDMockito.when(mockUserService.findAllUsers()).thenReturn(List.of());
		mockMvc.perform(MockMvcRequestBuilders.get("/usermgmt"))
				.andExpect(MockMvcResultMatchers.model().attribute("hasUsers", false))
				.andExpect(MockMvcResultMatchers.content()
						.string(Matchers.containsString("No users registered")));
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
		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/usermgmt/edit/123"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(
						MockMvcResultMatchers.model().attribute("roles", Matchers.contains(role)))
				.andExpect(
						MockMvcResultMatchers.content().string(Matchers.containsString(username)))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
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
						.param("rolesSubmitted", "true").param("roleIds", String.valueOf(role))
						.param("enabled", String.valueOf(enabled))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash()
						.attribute(WatchtowerModelAndView.FAILURE_NOTIFICATION,
								Matchers.containsString("Cannot find user")));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.USER_MODIFY_NAME}, username = "administrator")
	public void testUserEditTreatsMissingEnabledCheckboxAsDisabled() throws Exception {
		UserEntity user = createMockUser("target-user");
		BDDMockito.when(mockUserService.findById(BDDMockito.anyLong())).thenReturn(user);

		mockMvc.perform(MockMvcRequestBuilders.post("/usermgmt/edit")
						.param("id", "123").param("rolesSubmitted", "true")
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection());

		BDDMockito.verify(user).setEnabled(0);
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
						.param("rolesSubmitted", "true").param("roleIds", String.valueOf(role))
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
						.param("rolesSubmitted", "true").param("roleIds", String.valueOf(role))
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
						.param("rolesSubmitted", "true").param("roleIds", String.valueOf(role))
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
		RoleEntity adminRole = BDDMockito.mock(RoleEntity.class);

		BDDMockito.when(mockRoleService.findRoleById(BDDMockito.anyLong()))
				.thenReturn(adminRole);
		int id = 123;
		long role = 2L;
		int enabled = 1;
		mockMvc.perform(
				MockMvcRequestBuilders.post("/usermgmt/edit").param("id", String.valueOf(id))
						.param("rolesSubmitted", "true").param("roleIds", String.valueOf(role))
						.param("enabled", String.valueOf(enabled))
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andExpect(MockMvcResultMatchers.flash().attribute(
						WatchtowerModelAndView.SUCCESS_NOTIFICATION,
						Matchers.containsString(
								"User information for " + username + " saved successfully")));
		ArgumentCaptor<HashSet> roleCapture = ArgumentCaptor.forClass(HashSet.class);
		BDDMockito.verify(user).setRoles(roleCapture.capture());
		MatcherAssert.assertThat((HashSet<RoleEntity>) roleCapture.getValue(),
				Matchers.contains(adminRole));
	}

 @Test @WithMockUser(authorities = {CorePrivilege.USER_MODIFY_NAME})
 void completeRoleSetIsRequiredAndMalformedOrUnknownRolesCannotMutateUser() throws Exception {
  UserEntity user = createMockUser("target");
  BDDMockito.when(mockUserService.findById(123)).thenReturn(user);
  for (String role : List.of("", "not-an-id")) {
   var request = MockMvcRequestBuilders.post("/usermgmt/edit").param("id", "123").with(SecurityMockMvcRequestPostProcessors.csrf());
   if (!role.isEmpty()) request.param("rolesSubmitted", "true").param("roleIds", role);
   mockMvc.perform(request).andExpect(MockMvcResultMatchers.status().isBadRequest());
  }
  var valid = new RoleEntity();valid.setId(1);
  BDDMockito.when(mockRoleService.findRoleById(1)).thenReturn(valid);
  mockMvc.perform(MockMvcRequestBuilders.post("/usermgmt/edit").param("id", "123")
    .param("rolesSubmitted", "true").param("roleIds", "1", "999")
    .with(SecurityMockMvcRequestPostProcessors.csrf())).andExpect(MockMvcResultMatchers.flash().attributeExists("failure"));
  BDDMockito.verify(user, BDDMockito.never()).setRoles(BDDMockito.any());
  BDDMockito.verify(mockUserService, BDDMockito.never()).updateUser(BDDMockito.any());
 }
 @Test @WithMockUser(authorities = {CorePrivilege.USER_MODIFY_NAME, CorePrivilege.USER_VIEW_NAME})
 void multipleRolesRenderByIdAndSaveTogetherThenExplicitlyClear() throws Exception {
  UserEntity user = new UserEntity();org.springframework.test.util.ReflectionTestUtils.setField(user,"id",123L);user.setUsername("target");
  RoleEntity first = new RoleEntity();first.setId(1);first.setRoleName("First");
  RoleEntity sameId = new RoleEntity();sameId.setId(1);sameId.setRoleName("First");
  RoleEntity second = new RoleEntity();second.setId(2);second.setRoleName("Second");
  user.setRoles(new HashSet<>(List.of(first, second)));
  BDDMockito.when(mockUserService.findById(123)).thenReturn(user);
  BDDMockito.when(mockRoleService.findAllRoles()).thenReturn(List.of(sameId, second));
  BDDMockito.when(mockRoleService.findRoleById(1)).thenReturn(sameId);
  BDDMockito.when(mockRoleService.findRoleById(2)).thenReturn(second);
  var result = mockMvc.perform(MockMvcRequestBuilders.get("/usermgmt/edit/123")).andExpect(MockMvcResultMatchers.status().isOk()).andReturn();
  org.junit.jupiter.api.Assertions.assertEquals(2, org.jsoup.Jsoup.parse(result.getResponse().getContentAsString()).select("md-checkbox[name=roleIds][checked]").size());
  mockMvc.perform(MockMvcRequestBuilders.post("/usermgmt/edit").param("id", "123").param("rolesSubmitted", "true")
    .param("roleIds", "1", "2").with(SecurityMockMvcRequestPostProcessors.csrf())).andExpect(MockMvcResultMatchers.flash().attributeExists("success"));
  org.junit.jupiter.api.Assertions.assertEquals(java.util.Set.of(sameId, second), user.getRoles());
  mockMvc.perform(MockMvcRequestBuilders.post("/usermgmt/edit").param("id", "123").param("rolesSubmitted", "true")
    .with(SecurityMockMvcRequestPostProcessors.csrf())).andExpect(MockMvcResultMatchers.flash().attributeExists("success"));
  org.junit.jupiter.api.Assertions.assertTrue(user.getRoles().isEmpty());
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
