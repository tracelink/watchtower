package com.tracelink.appsec.module.betterleaks.allowlist;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingAction;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingContext;

public class BetterleaksAllowlistActionProviderTest {

	private final BetterleaksAllowlistActionProvider provider =
			new BetterleaksAllowlistActionProvider();

	private static Authentication user(String... authorities) {
		return new TestingAuthenticationToken("alice", null, authorities);
	}

	private static FindingContext finding(String rule, String file) {
		return new FindingContext("bb", "payments", rule, file, 12);
	}

	@Test
	public void testOffersAPrefilledAllowlistEntry() {
		Optional<FindingAction> action = provider.actionFor(
				finding("Betterleaks: aws-access-token", "src/config/app.yml"),
				user(BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME));

		Assertions.assertEquals(Optional.of(new FindingAction("Allowlist…",
				"/betterleaks/allowlist?repo=payments&path=src%2Fconfig%2Fapp.yml"
						+ "&rule=aws-access-token")), action);
	}

	@Test
	public void testEncodesValues() {
		FindingAction action = provider.actionFor(
				new FindingContext("bb", "my repo&x", "Betterleaks: r", "a b/c#d.yml", 1),
				user(BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)).orElseThrow();

		Assertions.assertEquals("/betterleaks/allowlist?repo=my+repo%26x&path=a+b%2Fc%23d.yml"
				+ "&rule=r", action.url());
	}

	@Test
	public void testNothingForOtherScannersFindings() {
		for (String rule : List.of("PMD: SomeRule", "Secrets: token", "")) {
			Assertions.assertEquals(Optional.empty(), provider.actionFor(
					finding(rule, "a.yml"), user(BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME)));
		}
	}

	@Test
	public void testNothingWithoutTheAllowlistPrivilege() {
		Assertions.assertEquals(Optional.empty(), provider.actionFor(
				finding("Betterleaks: aws-access-token", "a.yml"), user("Scan Results View")));
		Assertions.assertEquals(Optional.empty(), provider.actionFor(
				finding("Betterleaks: aws-access-token", "a.yml"), null));
	}
}
