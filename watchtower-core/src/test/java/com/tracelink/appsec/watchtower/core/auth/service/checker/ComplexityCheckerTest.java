package com.tracelink.appsec.watchtower.core.auth.service.checker;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.authentication.BadCredentialsException;

public class ComplexityCheckerTest {

	@ParameterizedTest
	@ValueSource(strings = {"aA1!", "aaaaaaAAAAA1111!!!!", "aZ0)", "‰3DLJIKLJLa"})
	void fullComplexitySuccess(String password) {
		try {
			new ComplexityUserPasswordRequirementsChecker(1, 1, 1, 1, 1).check(password);
		} catch (BadCredentialsException e) {
			Assertions.fail("Password " + password + " threw exception", e);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = {"",
		"a", "A", "1", "!",
		"aA", "a1", "a!", "A1", "A!", "1!",
		"aA1", "aA!", "a1!", "A1!"})
	void fullComplexityFails(String password) {
		try {
			new ComplexityUserPasswordRequirementsChecker(1, 1, 1, 1, 1).check(password);
			Assertions.fail("Password " + password + " should have thrown exception");
		} catch (BadCredentialsException e) {

		}
	}

	@ParameterizedTest
	@ValueSource(strings = {"aA1", "aA!", "a1!", "A1!"})
	void partialComplexitySuccess(String password) {
		try {
			new ComplexityUserPasswordRequirementsChecker(3, 0, 0, 0, 0).check(password);
		} catch (BadCredentialsException e) {
			Assertions.fail("Password " + password + " threw exception", e);
		}
	}

	@ParameterizedTest
	@ValueSource(strings = {"",
		"a", "A", "1", "!",
		"aA", "a1", "a!", "A1", "A!", "1!"})
	void partialComplexityFails(String password) {
		try {
			new ComplexityUserPasswordRequirementsChecker(3, 0, 0, 0, 0).check(password);
			Assertions.fail("Password " + password + " should have thrown exception");
		} catch (BadCredentialsException e) {

		}
	}

}
