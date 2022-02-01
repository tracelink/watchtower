package com.tracelink.appsec.watchtower.core.auth.service;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.model.RoleEntity;
import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.auth.repository.UserRepository;
import com.tracelink.appsec.watchtower.core.auth.service.checker.UserPasswordRequirementsChecker;

/**
 * Service that performs functions to update users in the database for user management. Also allows
 * access to list of users in the database.
 */
@Service
public class UserService implements UserDetailsService {
	public static final String DEFAULT_ADMIN_USER = "admin";

	private static final Logger LOGGER = LoggerFactory.getLogger(UserService.class);

	private final PasswordEncoder passwordEncoder;

	private final UserRepository userRepository;

	private final RoleService roleService;

	private final UserPasswordRequirementsChecker pwChecker;

	public UserService(@Autowired PasswordEncoder passwordEncoder,
			@Autowired UserRepository userRepository,
			@Autowired RoleService roleService,
			@Autowired UserPasswordRequirementsChecker pwChecker) {
		this.passwordEncoder = passwordEncoder;
		this.userRepository = userRepository;
		this.roleService = roleService;
		this.pwChecker = pwChecker;
	}

	void ensureDefaultUsers(RoleEntity adminRole) {
		UserEntity adminUser = findByUsername(DEFAULT_ADMIN_USER);
		// default admin exists
		if (adminUser != null) {
			// admin is currently enabled, change the pw
			if (adminUser.getEnabled() == 1) {
				String newAdminPassword = UUID.randomUUID().toString();
				adminUser.setPassword(passwordEncoder.encode(newAdminPassword));
				LOGGER.info(
						"\n\nNOTICE: 'admin' user must be disabled or removed after creating new admin users.\n'admin' password has been updated to '"
								+ newAdminPassword + "'\n");
			}
			// admin does not have the admin role, add it
			if (!adminUser.getRoles().contains(adminRole)) {
				adminUser.getRoles().add(adminRole);
			}
			// save the corrected admin user
			updateUser(adminUser);
		}
		// admin does not exist
		else {
			// if there are no other users with the admin role, remake the default admin
			if (findAllUsers().stream().noneMatch(u -> u.getRoles().contains(adminRole))) {
				String newAdminPassword = UUID.randomUUID().toString();
				registerNewUser(DEFAULT_ADMIN_USER, newAdminPassword);
				LOGGER.info(
						"NOTICE: No user found with admin role. A new user 'admin' has been created with password '"
								+ newAdminPassword
								+ "'. After logging in and creating a new, named user with the admin role, please disable this 'admin' user.");
			}
			// otherwise, there is at least 1 user with the admin role correctly configured
		}
	}

	public UserEntity findById(long id) {
		return userRepository.findById(id).orElse(null);
	}

	/**
	 * Returns a list of all users in the database.
	 *
	 * @return list of users in the database
	 */
	public List<UserEntity> findAllUsers() {
		return userRepository.findAll();
	}

	/**
	 * Gets the database user whose username matches the given username.
	 *
	 * @param username of user to be found
	 * @return user with the given username, if any
	 */
	public UserEntity findByUsername(String username) {
		return userRepository.findByUsername(username);
	}

	/**
	 * Adds a new user to the database. Hashes the password in the registration entity, sets the
	 * enabled flag, and sets the USER role. This should only be used for brand-new users
	 *
	 * @param username the user's username
	 * @param password the user's password
	 * @throws BadCredentialsException if the password does not meet the
	 *                                 {@linkplain UserPasswordRequirementsChecker} requirements
	 */
	public void registerNewUser(String username, String password) throws BadCredentialsException {
		UserEntity user = createUser(username, password);
		RoleEntity defaultUserRole = roleService.findDefaultRole();
		if (defaultUserRole != null) {
			user.setRoles(Collections.singleton(defaultUserRole));
		}
		userRepository.save(user);
	}

	private UserEntity createUser(String username, String password) throws BadCredentialsException {
		UserEntity user = new UserEntity();
		user.setCreated(new Date());
		user.setUsername(username);
		checkPasswordAllowed(password);
		user.setPassword(passwordEncoder.encode(password));
		user.setEnabled(1);
		return user;
	}

	private void checkPasswordAllowed(String password) throws BadCredentialsException {
		pwChecker.check(password);
	}

	/**
	 * Updates the given user in the database.
	 *
	 * @param user to be updated
	 */
	public void updateUser(UserEntity user) {
		user.setLastModified(new Date());
		userRepository.save(user);
	}

	/**
	 * Deletes the given user from the database.
	 *
	 * @param user to be deleted
	 */
	public void deleteUser(UserEntity user) {
		userRepository.delete(user);
	}

	/**
	 * Determines if the user associated with the given password has a password that matches the
	 * given password.
	 *
	 * @param user     the user to check
	 * @param password to compare with the user's password
	 * @return true if the given password matches the user's password, false otherwise
	 */
	public boolean checkPassword(UserEntity user, String password) {
		if (user != null) {
			return passwordEncoder.matches(password, user.getPassword());
		}
		return false;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		UserEntity user = userRepository.findByUsername(username);
		if (user == null) {
			throw new UsernameNotFoundException("Unknown username");
		}

		return buildUser(user.getUsername(), user.getPassword(), user);
	}

	UserDetails buildUser(String username, String password, UserEntity user) {
		return User.builder().username(username).password(password)
				.disabled(user.getEnabled() == 0)
				.accountExpired(false).accountLocked(false).credentialsExpired(false)
				.authorities(user.getRoles()
						.stream().flatMap(r -> r.getPrivileges().stream())
						.map(PrivilegeEntity::getName)
						.collect(Collectors.toList())
						.toArray(new String[]{}))
				.build();
	}

	/**
	 * Change a user's password given their username and current and new passwords
	 * 
	 * @param name            the user's username
	 * @param currentPassword the user's current password
	 * @param newPassword     the user's new password
	 * @throws AuthenticationException if the password cannot be changed
	 */
	public void changePassword(String name, String currentPassword, String newPassword)
			throws AuthenticationException {
		UserEntity user = findByUsername(name);
		if (user.getSsoId() != null) {
			throw new UsernameNotFoundException(
					"You cannot update your password if you authenticate using SSO.");
		}
		checkPasswordAllowed(newPassword);
		if (!checkPassword(user, currentPassword)) {
			throw new BadCredentialsException("Your current password is invalid");
		}
		user.setPassword(passwordEncoder.encode(newPassword));
		updateUser(user);
	}

	public UserEntity findBySsoId(String subject) {
		return userRepository.findBySsoId(subject);
	}

}
