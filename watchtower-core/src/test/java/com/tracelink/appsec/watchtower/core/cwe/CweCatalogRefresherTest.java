package com.tracelink.appsec.watchtower.core.cwe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.assistant.R1Database;

/** Refreshing the stored catalog from a fake publisher, over real Hibernate rows. */
class CweCatalogRefresherTest {
	private R1Database database;
	private CweCatalogStore store;
	private FakeClient client;
	private CweCatalogRefresher refresher;
	private final List<String> progress = new ArrayList<>();

	@BeforeEach
	void setUp() {
		database = new R1Database();
		store = database.service(new CweCatalogStore(database.repository(CweEntryRepository.class),
				database.repository(CweCatalogMetaRepository.class)));
		client = new FakeClient();
		refresher = new CweCatalogRefresher(client, store, Clock.fixed(Instant.parse("2026-10-26T12:00:00Z"), ZoneOffset.UTC));
		client.version = new CweCatalogClient.Version("4.20", "2026-04-30", 5);
		client.pillars = List.of(664, 707);
		client.below.put(664, Set.of(74, 79));
		client.below.put(707, Set.of(89));
		for (int id : List.of(664, 707, 74, 79, 89)) {
			client.catalog.put(id, entry(id, "Weakness " + id, "Allowed"));
		}
	}

	@AfterEach
	void tearDown() {
		database.close();
	}

	private static CweEntry entry(int id, String name, String usage) {
		return new CweEntry(id, name, "Base", "Simple", "Stable", usage, "About " + name, null, List.of());
	}

	@Test
	void theFirstRefreshStoresEveryWeaknessAndRemembersTheRelease() throws IOException {
		String message = refresher.refresh("alice", false, progress::add);

		assertThat(message).contains("4.20").contains("5");
		assertThat(store.all()).extracting(CweEntry::id).containsExactlyInAnyOrder(664, 707, 74, 79, 89);
		var meta = store.meta();
		assertThat(meta.getRefreshStatus()).isEqualTo(CweCatalogMetaEntity.OK);
		assertThat(meta.getContentVersion()).isEqualTo("4.20");
		assertThat(meta.getEntryCount()).isEqualTo(5);
		assertThat(meta.getRefreshedBy()).isEqualTo("alice");
		assertThat(meta.getFetchedAt()).isEqualTo(Instant.parse("2026-10-26T12:00:00Z").toEpochMilli());
		assertThat(progress).isNotEmpty();
	}

	@Test
	void downloadsInBatchesOfTwenty() throws IOException {
		client.version = new CweCatalogClient.Version("4.20", "2026-04-30", 45);
		client.pillars = List.of(1);
		Set<Integer> below = new LinkedHashSet<>();
		client.catalog.clear();
		for (int id = 1; id <= 45; id++) {
			client.catalog.put(id, entry(id, "Weakness " + id, "Allowed"));
			if (id > 1) {
				below.add(id);
			}
		}
		client.below.clear();
		client.below.put(1, below);

		refresher.refresh("alice", false, progress::add);

		assertThat(client.batches).extracting(List::size).containsExactly(20, 20, 5);
		assertThat(store.all()).hasSize(45);
	}

	@Test
	void anUnchangedReleaseIsNotDownloadedAgainUnlessForced() throws IOException {
		refresher.refresh("alice", false, progress::add);
		client.batches.clear();

		String skipped = refresher.refresh("bob", false, progress::add);

		assertThat(skipped).containsIgnoringCase("already current");
		assertThat(client.batches).isEmpty();
		assertThat(store.meta().getRefreshedBy()).isEqualTo("alice");

		refresher.refresh("bob", true, progress::add);

		assertThat(client.batches).isNotEmpty();
		assertThat(store.meta().getRefreshedBy()).isEqualTo("bob");
	}

	@Test
	void aNewReleaseReplacesTheOldSetRatherThanMergingIt() throws IOException {
		refresher.refresh("alice", false, progress::add);
		client.version = new CweCatalogClient.Version("4.21", "2026-10-01", 5);
		client.below.put(664, Set.of(74, 80));
		client.catalog.remove(79);
		client.catalog.put(80, entry(80, "Weakness 80", "Discouraged"));

		refresher.refresh("alice", false, progress::add);

		assertThat(store.all()).extracting(CweEntry::id).containsExactlyInAnyOrder(664, 707, 74, 80, 89);
		assertThat(store.all()).filteredOn(e -> e.id() == 80).singleElement().satisfies(e -> assertThat(e.isMappable()).isFalse());
		assertThat(store.meta().getContentVersion()).isEqualTo("4.21");
	}

	@Test
	void aFailureKeepsTheOldCatalogAndSaysWhy() throws IOException {
		refresher.refresh("alice", false, progress::add);
		client.version = new CweCatalogClient.Version("4.21", "2026-10-01", 5);
		client.failure = new IOException("MITRE did not answer after 3 tries (HTTP 503)");

		assertThatThrownBy(() -> refresher.refresh("alice", false, progress::add)).isInstanceOf(IOException.class)
				.hasMessageContaining("503");

		assertThat(store.all()).hasSize(5);
		var meta = store.meta();
		assertThat(meta.getRefreshStatus()).isEqualTo(CweCatalogMetaEntity.FAILED);
		assertThat(meta.getLastError()).contains("503");
		assertThat(meta.getContentVersion()).isEqualTo("4.20");
	}

	@Test
	void refusesAnUpdateThatWouldShrinkTheCatalogByMoreThanAFifth() throws IOException {
		refresher.refresh("alice", false, progress::add);
		client.version = new CweCatalogClient.Version("4.21", "2026-10-01", 5);
		client.below.put(664, Set.of());
		client.below.put(707, Set.of());

		assertThatThrownBy(() -> refresher.refresh("alice", false, progress::add)).hasMessageContaining("fewer");

		assertThat(store.all()).hasSize(5);
		assertThat(store.meta().getRefreshStatus()).isEqualTo(CweCatalogMetaEntity.FAILED);
	}

	@Test
	void refusesAFirstLoadThatHoldsFarFewerWeaknessesThanTheReleaseSays() {
		client.version = new CweCatalogClient.Version("4.20", "2026-04-30", 969);

		assertThatThrownBy(() -> refresher.refresh("alice", false, progress::add)).hasMessageContaining("fewer");

		assertThat(store.all()).isEmpty();
	}

	@Test
	void anUnexpectedErrorIsRecordedWithoutLeakingItsMessage() {
		client.unexpected = new IllegalStateException("jdbc:mysql://secret-host/db password=hunter2");

		assertThatThrownBy(() -> refresher.refresh("alice", false, progress::add)).isInstanceOf(IOException.class)
				.hasMessageNotContaining("hunter2");

		assertThat(store.meta().getLastError()).doesNotContain("hunter2");
	}

	/** A publisher that answers from memory and remembers how it was asked. */
	private static final class FakeClient implements CweCatalogClient {
		Version version;
		List<Integer> pillars = List.of();
		final Map<Integer, Set<Integer>> below = new LinkedHashMap<>();
		final Map<Integer, CweEntry> catalog = new LinkedHashMap<>();
		final List<List<Integer>> batches = new ArrayList<>();
		IOException failure;
		RuntimeException unexpected;

		@Override
		public Version version() throws IOException {
			if (unexpected != null) {
				throw unexpected;
			}
			return version;
		}

		@Override
		public List<Integer> topLevelIds() {
			return pillars;
		}

		@Override
		public Set<Integer> descendantIds(int id) {
			return below.getOrDefault(id, Set.of());
		}

		@Override
		public List<CweEntry> weaknesses(List<Integer> ids) throws IOException {
			if (failure != null) {
				throw failure;
			}
			batches.add(List.copyOf(ids));
			return ids.stream().map(catalog::get).filter(java.util.Objects::nonNull).toList();
		}
	}
}
