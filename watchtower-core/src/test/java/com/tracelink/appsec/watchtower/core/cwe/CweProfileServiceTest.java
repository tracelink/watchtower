package com.tracelink.appsec.watchtower.core.cwe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.assistant.R1Database;

/** The CWE profile and the gap decisions, over real rows and a mocked catalog. */
class CweProfileServiceTest {
	private R1Database database;
	private CweCatalogService catalog;
	private CweProfileService service;

	@BeforeEach
	void setUp() {
		database = new R1Database();
		catalog = mock(CweCatalogService.class);
		when(catalog.isLoaded()).thenReturn(true);
		known(89, "SQL Injection", "Allowed");
		known(79, "Cross-site Scripting", "Allowed");
		known(74, "Injection", "Discouraged");
		when(catalog.find("CWE-99999")).thenReturn(Optional.empty());
		service = database.service(new CweProfileService(database.repository(CweProfileEntryRepository.class),
				database.repository(CweGapDecisionRepository.class), catalog,
				Clock.fixed(Instant.parse("2026-10-27T10:00:00Z"), ZoneOffset.UTC)));
	}

	@AfterEach
	void tearDown() {
		database.close();
	}

	private void known(int id, String name, String usage) {
		var entry = new CweEntry(id, name, "Base", "Simple", "Stable", usage, "d", null, List.of());
		when(catalog.find("CWE-" + id)).thenReturn(Optional.of(entry));
		when(catalog.find(String.valueOf(id))).thenReturn(Optional.of(entry));
	}

	@Test
	void addingAWeaknessStoresItWithItsPriorityAndNameAndIsIdempotent() {
		var entry = service.add("cwe-89", "CRITICAL", "  our biggest risk ", "alice");
		service.add("CWE-89", "HIGH", null, "bob");

		assertThat(entry.cwe()).isEqualTo(89);
		assertThat(entry.label()).isEqualTo("CWE-89");
		assertThat(entry.name()).isEqualTo("SQL Injection");
		assertThat(entry.note()).isEqualTo("our biggest risk");
		var stored = service.list();
		assertThat(stored).hasSize(1);
		assertThat(stored.get(0).priority()).isEqualTo("HIGH");
	}

	@Test
	void aWeaknessMitreDiscouragesCanStillBeInTheProfile() {
		assertThat(service.add("CWE-74", "NORMAL", null, "alice").name()).isEqualTo("Injection");
	}

	@Test
	void unknownMalformedAndBadInputIsRefusedWithAMessage() {
		assertThatThrownBy(() -> service.add("CWE-99999", "HIGH", null, "a")).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("catalog");
		assertThatThrownBy(() -> service.add("not a cwe", "HIGH", null, "a")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> service.add("CWE-89", "URGENT", null, "a")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> service.add("CWE-89", "HIGH", "x".repeat(256), "a")).isInstanceOf(IllegalArgumentException.class);
		assertThat(service.list()).isEmpty();
	}

	@Test
	void withoutTheCatalogOnlyTheTop25CanBeAdded() {
		when(catalog.isLoaded()).thenReturn(false);

		assertThat(service.add("CWE-79", "CRITICAL", null, "alice").name()).isNotBlank();
		assertThatThrownBy(() -> service.add("CWE-1004", "HIGH", null, "a")).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("Load the CWE catalog");
	}

	@Test
	void theTop25AreAddedInPriorityBandsAndAddingThemTwiceAddsNothing() {
		int first = service.addTop25("alice");
		int second = service.addTop25("alice");

		assertThat(first).isEqualTo(25);
		assertThat(second).isZero();
		var all = service.list();
		assertThat(all).hasSize(25);
		assertThat(all).extracting(CweProfileService.Entry::priority).containsSubsequence("CRITICAL", "HIGH", "NORMAL");
		assertThat(all.stream().filter(e -> e.priority().equals("CRITICAL")).count()).isEqualTo(10);
		assertThat(all.stream().filter(e -> e.priority().equals("HIGH")).count()).isEqualTo(10);
		assertThat(all.stream().filter(e -> e.priority().equals("NORMAL")).count()).isEqualTo(5);
	}

	@Test
	void theProfileIsListedMostImportantFirstThenByNumber() {
		service.add("CWE-89", "NORMAL", null, "a");
		service.add("CWE-79", "CRITICAL", null, "a");
		service.add("CWE-74", "CRITICAL", null, "a");

		assertThat(service.list()).extracting(CweProfileService.Entry::cwe).containsExactly(74, 79, 89);
	}

	@Test
	void theProfileHasAnUpperBound() {
		for (int id = 1; id <= CweProfileService.MAX_ENTRIES; id++) {
			var entry = new CweEntry(id, "Weakness " + id, "Base", "Simple", "Stable", "Allowed", "d", null, List.of());
			when(catalog.find("CWE-" + id)).thenReturn(Optional.of(entry));
			service.add("CWE-" + id, "NORMAL", null, "a");
		}
		var extra = new CweEntry(500, "Extra", "Base", "Simple", "Stable", "Allowed", "d", null, List.of());
		when(catalog.find("CWE-500")).thenReturn(Optional.of(extra));

		assertThatThrownBy(() -> service.add("CWE-500", "NORMAL", null, "a")).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining(String.valueOf(CweProfileService.MAX_ENTRIES));
		assertThat(service.add("CWE-1", "HIGH", null, "a").priority()).as("changing one already there is still fine").isEqualTo("HIGH");
	}

	@Test
	void removingAWeaknessAlsoRemovesItsDecisions() {
		service.add("CWE-89", "HIGH", null, "a");
		service.add("CWE-79", "HIGH", null, "a");
		service.decide("CWE-89", "PYTHON", "NOT_APPLICABLE", null, "a");
		service.decide("CWE-79", "PYTHON", "DEFERRED", null, "a");

		service.remove("CWE-89");

		assertThat(service.list()).extracting(CweProfileService.Entry::cwe).containsExactly(79);
		assertThat(service.decisions()).extracting(CweProfileService.Decision::cwe).containsExactly(79);
	}

	@Test
	void aDecisionIsStoredPerLanguageReplacedAndCleared() {
		service.add("CWE-89", "HIGH", null, "a");

		var first = service.decide("CWE-89", "java", "NOT_COVERABLE", " needs taint tracking ", "alice");
		service.decide("CWE-89", "JAVA", "DEFERRED", null, "bob");
		service.decide("CWE-89", "PYTHON", "NOT_APPLICABLE", null, "bob");

		assertThat(first.language()).isEqualTo("JAVA");
		assertThat(first.note()).isEqualTo("needs taint tracking");
		assertThat(service.decisions()).extracting(CweProfileService.Decision::decision).containsExactlyInAnyOrder("DEFERRED",
				"NOT_APPLICABLE");

		service.clearDecision("CWE-89", "JAVA");

		assertThat(service.decisions()).extracting(CweProfileService.Decision::language).containsExactly("PYTHON");
	}

	@Test
	void aDecisionNeedsAProfileWeaknessAValidLanguageAndAValidDecision() {
		assertThatThrownBy(() -> service.decide("CWE-89", "JAVA", "DEFERRED", null, "a")).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("profile");
		service.add("CWE-89", "HIGH", null, "a");
		assertThatThrownBy(() -> service.decide("CWE-89", "COBOL", "DEFERRED", null, "a")).isInstanceOf(IllegalArgumentException.class);
		assertThatThrownBy(() -> service.decide("CWE-89", "JAVA", "SOMEDAY", null, "a")).isInstanceOf(IllegalArgumentException.class);
		assertThat(service.decisions()).isEmpty();
	}
}
