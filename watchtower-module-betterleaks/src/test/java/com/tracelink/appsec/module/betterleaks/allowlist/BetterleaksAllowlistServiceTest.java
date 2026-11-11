package com.tracelink.appsec.module.betterleaks.allowlist;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;

import com.tracelink.appsec.watchtower.test.logging.LogWatchExtension;

public class BetterleaksAllowlistServiceTest {

	private static final Instant NOW = Instant.parse("2026-09-25T12:00:00Z");

	@RegisterExtension
	LogWatchExtension logWatcher = LogWatchExtension.forClass(BetterleaksAllowlistService.class);

	private BetterleaksAllowlistRepository repository;

	private BetterleaksAllowlistService service;

	@BeforeEach
	public void setup() {
		repository = BDDMockito.mock(BetterleaksAllowlistRepository.class);
		BDDMockito.when(repository.save(BDDMockito.any()))
				.thenAnswer(invocation -> invocation.getArgument(0));
		service = new BetterleaksAllowlistService(repository, Clock.fixed(NOW, ZoneOffset.UTC));
	}

	private static BetterleaksAllowlistRequest request(BetterleaksAllowlistScope scope,
			String repo, String glob, String rule, String reason, LocalDate expiresOn) {
		return new BetterleaksAllowlistRequest(scope, repo, glob, rule, reason, expiresOn);
	}

	private BetterleaksAllowlistEntryEntity saved() {
		ArgumentCaptor<BetterleaksAllowlistEntryEntity> captor =
				ArgumentCaptor.forClass(BetterleaksAllowlistEntryEntity.class);
		BDDMockito.verify(repository).save(captor.capture());
		return captor.getValue();
	}

	@Test
	public void testAddsARepoScopedPathEntryWithItsAuthorAndExpiry() {
		service.addEntry(request(BetterleaksAllowlistScope.REPO, " payments ", "src/test/**",
				"github-pat", " fixture tokens ", LocalDate.of(2026, 10, 1)), "alice");

		BetterleaksAllowlistEntryEntity entity = saved();
		Assertions.assertEquals(BetterleaksAllowlistScope.REPO, entity.getScope());
		Assertions.assertEquals("payments", entity.getRepoName());
		Assertions.assertEquals("src/test/**", entity.getPathGlob());
		Assertions.assertEquals("github-pat", entity.getRuleId());
		Assertions.assertEquals("fixture tokens", entity.getReason());
		Assertions.assertEquals("alice", entity.getCreatedBy());
		Assertions.assertEquals(NOW.toEpochMilli(), entity.getCreatedAt());
		// Valid through the whole expiry day.
		Assertions.assertEquals(Instant.parse("2026-10-02T00:00:00Z").toEpochMilli(),
				entity.getExpiresAt());
		MatcherAssert.assertThat(String.join("\n", logWatcher.getFormattedMessages()),
				Matchers.allOf(Matchers.containsString("alice"),
						Matchers.containsString("src/test/**")));
	}

	@Test
	public void testGlobalEntryIgnoresARepoName() {
		service.addEntry(request(BetterleaksAllowlistScope.GLOBAL, "payments", "*.lock", null,
				"lockfile hashes", null), "alice");

		Assertions.assertNull(saved().getRepoName());
		Assertions.assertNull(saved().getExpiresAt());
	}

	@Test
	public void testRejectsInvalidRequests() {
		String reason = "because";
		List<BetterleaksAllowlistRequest> invalid = List.of(
				request(null, null, "src/**", null, reason, null),
				request(BetterleaksAllowlistScope.REPO, " ", "src/**", null, reason, null),
				request(BetterleaksAllowlistScope.GLOBAL, null, null, null, reason, null),
				request(BetterleaksAllowlistScope.GLOBAL, null, "**", null, reason, null),
				request(BetterleaksAllowlistScope.GLOBAL, null, "src/**", "no-such-rule", reason,
						null),
				request(BetterleaksAllowlistScope.GLOBAL, null, "src/**", null, " ", null),
				request(BetterleaksAllowlistScope.GLOBAL, null, "src/**", null, "x".repeat(501),
						null),
				request(BetterleaksAllowlistScope.GLOBAL, null, "src/**", null, reason,
						LocalDate.of(2026, 9, 24)),
				request(BetterleaksAllowlistScope.GLOBAL, null, "src/**", null, reason,
						LocalDate.of(2027, 9, 26)),
				request(BetterleaksAllowlistScope.REPO, "a".repeat(256), "src/**", null, reason,
						null));

		for (BetterleaksAllowlistRequest bad : invalid) {
			Assertions.assertThrows(IllegalArgumentException.class,
					() -> service.addEntry(bad, "alice"), bad.toString());
		}
		BDDMockito.verify(repository, BDDMockito.never()).save(BDDMockito.any());
	}

	@Test
	public void testActiveEntriesAreGlobalPlusThisReposUnexpiredEntries() {
		BetterleaksAllowlistEntryEntity global = entity(BetterleaksAllowlistScope.GLOBAL, null,
				"*.lock", null, null);
		BetterleaksAllowlistEntryEntity mine = entity(BetterleaksAllowlistScope.REPO, "Payments",
				"src/test/**", "github-pat", NOW.plusSeconds(60).toEpochMilli());
		BetterleaksAllowlistEntryEntity other = entity(BetterleaksAllowlistScope.REPO, "billing",
				"src/**", null, null);
		BetterleaksAllowlistEntryEntity expired = entity(BetterleaksAllowlistScope.GLOBAL, null,
				"docs/**", null, NOW.minusSeconds(1).toEpochMilli());
		BDDMockito.when(repository.findAll()).thenReturn(List.of(global, mine, other, expired));

		List<BetterleaksAllowlistEntry> active = service.activeEntries("payments");

		Assertions.assertEquals(List.of(
				new BetterleaksAllowlistEntry(BetterleaksAllowlistScope.GLOBAL, null, "*.lock",
						null),
				new BetterleaksAllowlistEntry(BetterleaksAllowlistScope.REPO, "Payments",
						"src/test/**", "github-pat")), active);
	}

	@Test
	public void testScanWithoutARepositoryGetsOnlyGlobalEntries() {
		BDDMockito.when(repository.findAll()).thenReturn(List.of(
				entity(BetterleaksAllowlistScope.GLOBAL, null, "*.lock", null, null),
				entity(BetterleaksAllowlistScope.REPO, "payments", "src/**", null, null)));

		Assertions.assertEquals(1, service.activeEntries(null).size());
	}

	@Test
	public void testDeleteLogsWhoRemovedWhat() {
		BetterleaksAllowlistEntryEntity entry = entity(BetterleaksAllowlistScope.GLOBAL, null,
				"*.lock", null, null);
		BDDMockito.when(repository.findById(3L)).thenReturn(Optional.of(entry));

		service.deleteEntry(3L, "bob");

		BDDMockito.verify(repository).delete(entry);
		MatcherAssert.assertThat(String.join("\n", logWatcher.getFormattedMessages()),
				Matchers.allOf(Matchers.containsString("bob"), Matchers.containsString("*.lock")));
	}

	@Test
	public void testDeletingAMissingEntryFails() {
		BDDMockito.when(repository.findById(3L)).thenReturn(Optional.empty());

		Assertions.assertThrows(IllegalArgumentException.class,
				() -> service.deleteEntry(3L, "bob"));
	}

	private static BetterleaksAllowlistEntryEntity entity(BetterleaksAllowlistScope scope,
			String repo, String glob, String rule, Long expiresAt) {
		BetterleaksAllowlistEntryEntity entity = new BetterleaksAllowlistEntryEntity();
		entity.setScope(scope);
		entity.setRepoName(repo);
		entity.setPathGlob(glob);
		entity.setRuleId(rule);
		entity.setReason("reason");
		entity.setCreatedBy("alice");
		entity.setCreatedAt(NOW.toEpochMilli());
		entity.setExpiresAt(expiresAt);
		return entity;
	}
}
