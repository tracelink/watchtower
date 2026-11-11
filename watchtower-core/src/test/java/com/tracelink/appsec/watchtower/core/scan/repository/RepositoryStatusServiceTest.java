package com.tracelink.appsec.watchtower.core.scan.repository;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;
import org.mockito.Mockito;

import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;

public class RepositoryStatusServiceTest {

	private static final long NOW = 1_800_000_000_000L;

	private static final long DAY = 86_400_000L;

	private ApiIntegrationService integrations;

	private RepositoryStatusService statuses;

	@BeforeEach
	public void setup() {
		integrations = Mockito.mock(ApiIntegrationService.class);
		ApiIntegrationEntity bb = Mockito.mock(ApiIntegrationEntity.class);
		BDDMockito.when(bb.getApiLabel()).thenReturn("bb");
		BDDMockito.when(integrations.getAllSettings()).thenReturn(List.of(bb));
		statuses = new RepositoryStatusService(integrations, 30,
				Clock.fixed(Instant.ofEpochMilli(NOW), ZoneOffset.UTC));
	}

	@Test
	public void theFirstMatchingStatusWins() {
		RepositoryEntity orphanedGonePaused = repo("old", false, true, NOW - 90 * DAY);
		Assertions.assertEquals(RepoStatus.ORPHANED, statuses.statusOf(orphanedGonePaused));
		Assertions.assertEquals(RepoStatus.GONE,
				statuses.statusOf(repo("bb", false, true, NOW - 90 * DAY)));
		Assertions.assertEquals(RepoStatus.PAUSED,
				statuses.statusOf(repo("bb", true, true, NOW - 90 * DAY)));
		Assertions.assertEquals(RepoStatus.INACTIVE,
				statuses.statusOf(repo("bb", true, false, NOW - 31 * DAY)));
		Assertions.assertEquals(RepoStatus.ACTIVE,
				statuses.statusOf(repo("bb", true, false, NOW - 29 * DAY)));
		Assertions.assertEquals(RepoStatus.ACTIVE, statuses.statusOf(repo("bb", true, false, 0)),
				"a repository that never had a pull request is not inactive");
	}

	@Test
	public void anIntegrationNameDifferingOnlyInCaseIsNotOrphaned() {
		// The database, and so the tabs, compare names ignoring case
		Assertions.assertFalse(statuses.isOrphaned("BB"));
		Assertions.assertEquals(RepoStatus.ACTIVE, statuses.statusOf(repo("Bb", true, false, 0)));
		Assertions.assertTrue(statuses.isOrphaned("bbx"));
		Assertions.assertTrue(statuses.isOrphaned(null));
	}

	@Test
	public void reasonsSayWhy() {
		Assertions.assertEquals("No pull requests yet. Repository scans still cover it.",
				statuses.reason(repo("bb", true, false, 0)));
		Assertions.assertEquals("No pull request for 45 d (more than 30 days).",
				statuses.reason(repo("bb", true, false, NOW - 45 * DAY)));
		Assertions.assertTrue(statuses.reason(repo("old", true, false, 0)).contains("old"));
	}

	@Test
	public void integrationNamesAreCachedForAMinute() {
		statuses.integrationLabels();
		statuses.integrationLabels();
		BDDMockito.verify(integrations, BDDMockito.times(1)).getAllSettings();
		statuses.forgetIntegrations();
		statuses.integrationLabels();
		BDDMockito.verify(integrations, BDDMockito.times(2)).getAllSettings();
	}

	@Test
	public void agoIsShort() {
		Assertions.assertEquals("never", statuses.ago(0));
		Assertions.assertEquals("5 min", statuses.ago(NOW - 5 * 60_000L));
		Assertions.assertEquals("3 h", statuses.ago(NOW - 3 * 3_600_000L));
		Assertions.assertEquals("3 d", statuses.ago(NOW - 3 * DAY));
		Assertions.assertEquals("2 y", statuses.ago(NOW - 800 * DAY));
	}

	@Test
	public void searchTakesSelectorTokens() {
		RepositoryFilter filter = RepositoryFilter.of("  pay  label:PCI team:checkout"
				+ " project:PAY api ", "paused", "");
		Assertions.assertEquals("pay api", filter.text());
		Assertions.assertEquals("pci", filter.label());
		Assertions.assertEquals("checkout", filter.team());
		Assertions.assertEquals("PAY", filter.project());
		Assertions.assertEquals(RepoStatus.PAUSED, filter.status());

		RepositoryFilter menu = RepositoryFilter.of("label:pci", "nonsense", "sox");
		Assertions.assertEquals("sox", menu.label(), "the label menu wins over the token");
		Assertions.assertNull(menu.status());
		Assertions.assertTrue(RepositoryFilter.of(" ", "", null).isEmpty());
		Assertions.assertEquals(128, RepositoryFilter.of("x".repeat(500), "", null).text()
				.length());
	}

	@Test
	public void likeWildcardsAreEscaped() {
		Assertions.assertEquals("pay\\_api\\%\\\\", RepositoryStatusService.escapeLike(
				"pay_api%\\"));
	}

	@Test
	public void imageRepositoriesUseImageScanWording() {
		RepositoryEntity image = repo("bb", true, false, NOW - 45 * DAY);
		image.setScanType(com.tracelink.appsec.watchtower.core.scan.image.ImageScanType.CONTAINER);
		Assertions.assertEquals("No image scan for 45 d (more than 30 days).", statuses.reason(image));
		Assertions.assertEquals("No recent image scans", statuses.statusOf(image).labelFor(true));
		Assertions.assertEquals("No recent PRs", statuses.statusOf(image).labelFor(false));
		image.setLastReviewedDate(0);
		Assertions.assertEquals("No image scans yet.", statuses.reason(image));
		image.setScanningPaused(true);
		Assertions.assertEquals("Scanning is paused: new images are not scanned.", statuses.reason(image));
	}

	private static RepositoryEntity repo(String apiLabel, boolean enabled, boolean paused,
			long lastPr) {
		RepositoryEntity repo = new RepositoryEntity();
		repo.setApiLabel(apiLabel);
		repo.setRepoName("r");
		repo.setEnabled(enabled);
		repo.setScanningPaused(paused);
		repo.setLastReviewedDate(lastPr);
		return repo;
	}
}
