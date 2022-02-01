package com.tracelink.appsec.watchtower.core.auth.service.checker;

import org.springframework.security.authentication.BadCredentialsException;

/**
 * A User password checker to check that passwords are within policy
 * 
 * @author csmith
 *
 */
public interface UserPasswordRequirementsChecker {
	/**
	 * Check if the password meets the requirements, throw exception if the password is bad
	 * 
	 * @param password the password to check
	 * @throws BadCredentialsException if the password is bad
	 */
	public void check(String password) throws BadCredentialsException;

	/**
	 * Get a user-friendly string describing the requirements of the password
	 * 
	 * @return
	 */
	public String getRequirementsStatement();
}
