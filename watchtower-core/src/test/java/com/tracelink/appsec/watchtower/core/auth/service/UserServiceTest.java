package com.tracelink.appsec.watchtower.core.auth.service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.stream.Collectors;

import javax.security.sasl.AuthenticationException;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.repository.UserRepository;

@ExtendWith(SpringExtension.class)
public class UserServiceTest {
	private UserService userService;

	private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

	@MockBean
	private UserRepository mockUserRepository;

	@MockBean
	private RoleService mockRoleService;



	@BeforeEach
	public void setup() {
		this.userService = new UserService(passwordEncoder, mockUserRepository,
				mockRoleService);
	}

	@Test
	public void testFindById() {
		userService.findById(123);
		BDDMockito.verify(mockUserRepository).findById(BDDMockito.anyLong());
	}

	@Test
	public void testFindAllUsers() {
		userService.findAllUsers();
		BDDMockito.verify(mockUserRepository).findAll();
	}

	@Test
	public void testFindByUsername() {
		userService.findByUsername("");
		BDDMockito.verify(mockUserRepository).findByUsername(BDDMockito.anyString());
	}

	@Test
	public void testSaveNewUser() {
		String pass = "foobar";
		RoleEntity role = new RoleEntity();
		BDDMockito.when(mockRoleService.findDefaultRole()).thenReturn(role);
		ArgumentCaptor<UserEntity> userCaptor = ArgumentCaptor.forClass(UserEntity.class);
		userService.registerNewUser("user", pass);
		BDDMockito.verify(mockUserRepository).save(userCaptor.capture());
		Assertions.assertTrue(passwordEncoder.matches(pass, userCaptor.getValue().getPassword()));
		Assertions.assertTrue(userCaptor.getValue().getRoles().contains(role));
	}


	@Test
	public void testUpdateUser() {
		UserEntity user = new UserEntity();
		userService.updateUser(user);
		BDDMockito.verify(mockUserRepository).save(BDDMockito.any(UserEntity.class));
	}

	@Test
	public void testDeleteUser() {
		userService.deleteUser(new UserEntity());
		BDDMockito.verify(mockUserRepository).delete(BDDMockito.any(UserEntity.class));
	}

	@Test
	public void testCheckPasswordNull() {
		Assertions.assertFalse(userService.checkPassword(null, ""));
	}

	@Test
	public void testCheckPasswordMismatch() {
		UserEntity user = new UserEntity();
		user.setPassword("SOMETHING");
		Assertions.assertFalse(userService.checkPassword(user, "OTHER"));
	}

	@Test
	public void testCheckPasswordSuccess() {
		UserEntity user = new UserEntity();
		String pw = "SOMETHING";
		user.setPassword(passwordEncoder.encode(pw));
		Assertions.assertTrue(userService.checkPassword(user, pw));
	}

	@Test
	public void testLoadUserByUsernameSuccess() {
		String username = "user";
		String password = "myPass";
		String privName1 = "priv1";
		String privName2 = "priv2";

		RoleEntity role = new RoleEntity().setRoleName("1");
		role.getPrivileges().add(new PrivilegeEntity().setName(privName1));
		RoleEntity role2 = new RoleEntity().setRoleName("2");
		role2.getPrivileges().add(new PrivilegeEntity().setName(privName2));

		UserEntity user = new UserEntity();
		user.setUsername(username);
		user.setPassword(password);
		user.setRoles(new HashSet<>(Arrays.asList(role, role2)));

		BDDMockito.when(mockUserRepository.findByUsername(BDDMockito.anyString())).thenReturn(user);

		UserDetails springUser = userService.loadUserByUsername(username);

		Assertions.assertEquals(username, springUser.getUsername());
		Assertions.assertEquals(password, springUser.getPassword());
		MatcherAssert.assertThat(
				springUser.getAuthorities().stream().map(GrantedAuthority::getAuthority)
						.collect(Collectors.toList()),
				Matchers.contains(privName1, privName2));
	}

	@Test
	public void testLoadUserByUsernameNoUser() {
		Assertions.assertThrows(UsernameNotFoundException.class,
				() -> {
					BDDMockito.when(mockUserRepository.findByUsername(BDDMockito.anyString()))
							.thenReturn(null);
					userService.loadUserByUsername("");
				});
	}

	@Test
	public void testChangePasswordSuccess() throws AuthenticationException {
		UserEntity user = new UserEntity();
		String oldpass = "foo";
		String newpass = "bar";
		user.setPassword(passwordEncoder.encode(oldpass));
		BDDMockito.when(mockUserRepository.findByUsername(BDDMockito.anyString())).thenReturn(user);

		userService.changePassword("user", oldpass, newpass);

		Assertions.assertTrue(passwordEncoder.matches(newpass, user.getPassword()));
	}

	@Test
	public void testChangePasswordFailSSO() {
		UserEntity user = new UserEntity();
		String oldpass = "foo";
		String newpass = "bar";
		user.setSsoId("ssoid");
		BDDMockito.when(mockUserRepository.findByUsername(BDDMockito.anyString())).thenReturn(user);
		try {
			userService.changePassword("user", oldpass, newpass);
			Assertions.fail("Should throw exception");
		} catch (AuthenticationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("authenticate using SSO"));
		}
	}

	@Test
	public void testChangePasswordFailBadPw() {
		UserEntity user = new UserEntity();
		String oldpass = "foo";
		String newpass = "bar";
		user.setPassword(passwordEncoder.encode(oldpass));
		BDDMockito.when(mockUserRepository.findByUsername(BDDMockito.anyString())).thenReturn(user);
		try {
			userService.changePassword("user", "wrong", newpass);
			Assertions.fail("Should throw exception");
		} catch (AuthenticationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.containsString("password is invalid"));
		}
	}

}
