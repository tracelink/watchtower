package com.tracelink.appsec.watchtower.core.auth.service.checker;

import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.Assert;

/**
 * User Password Complexity Checker to test for length and character types
 * 
 * @author csmith
 *
 */
public class ComplexityUserPasswordRequirementsChecker implements UserPasswordRequirementsChecker {
	private final int length;
	private final int capitals;
	private final int numbers;
	private final int specials;
	private final int lowers;

	public ComplexityUserPasswordRequirementsChecker(int length, int capitals, int numbers,
			int specials, int lowers) {
		Assert.isTrue(length >= 0, "length must be a non-negative integer");
		Assert.isTrue(capitals >= 0, "capitals must be a non-negative integer");
		Assert.isTrue(numbers >= 0, "numbers must be a non-negative integer");
		Assert.isTrue(specials >= 0, "specials must be a non-negative integer");
		Assert.isTrue(lowers >= 0, "lowers must be a non-negative integer");

		this.length = length;
		this.capitals = capitals;
		this.numbers = numbers;
		this.specials = specials;
		this.lowers = lowers;
	}

	@Override
	public void check(String password) throws BadCredentialsException {
		if (password.length() < this.length) {
			throw new BadCredentialsException("Password does not meet minimum length requirements");
		}
		AtomicInteger countLower = new AtomicInteger(this.lowers);
		AtomicInteger countUpper = new AtomicInteger(this.capitals);
		AtomicInteger countNumber = new AtomicInteger(this.numbers);
		AtomicInteger countSpecial = new AtomicInteger(this.specials);

		password.chars().forEach(c -> {
			if (Character.isLowerCase(c)) {
				countLower.decrementAndGet();
			} else if (Character.isUpperCase(c)) {
				countUpper.decrementAndGet();
			} else if (Character.isDigit(c)) {
				countNumber.decrementAndGet();
			} else {
				countSpecial.decrementAndGet();
			}
		});

		if (countLower.intValue() > 0 || countUpper.intValue() > 0 || countNumber.intValue() > 0
				|| countSpecial.intValue() > 0) {
			throw new BadCredentialsException("Password does not meet complexity requirements");
		}
	}

	@Override
	public String getRequirementsStatement() {
		StringBuilder sb = new StringBuilder();
		if (length > 0) {
			sb.append(length + " characters, ");
		}
		if (capitals > 0) {
			sb.append(capitals + " capital letters, ");
		}
		if (numbers > 0) {
			sb.append(numbers + " numbers, ");
		}
		if (specials > 0) {
			sb.append(specials + " special characters, ");
		}
		if (lowers > 0) {
			sb.append(lowers + " lowercase letters, ");
		}
		if (sb.length() > 0) {
			return "A password must have at least " + sb.substring(0, sb.length() - 2);
		}
		return "";
	}

}
