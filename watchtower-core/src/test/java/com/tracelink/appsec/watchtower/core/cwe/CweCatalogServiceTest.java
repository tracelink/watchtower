package com.tracelink.appsec.watchtower.core.cwe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobStatus;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;

/** Looking CWEs up, validating them and shortlisting by words, from a stored catalog. */
class CweCatalogServiceTest {
	private CweCatalogStore store;
	private AsyncJobService jobs;
	private CweCatalogService service;
	private CweCatalogMetaEntity meta;

	@SuppressWarnings("unchecked")
	@BeforeEach
	void setUp() throws Exception {
		store = mock(CweCatalogStore.class);
		jobs = mock(AsyncJobService.class);
		ObjectProvider<AsyncJobService> provider = mock(ObjectProvider.class);
		when(provider.getObject()).thenReturn(jobs);
		meta = loadedMeta();
		when(store.meta()).thenReturn(meta);
		when(store.all()).thenReturn(List.of(
				entry(79, "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", "Base", "Allowed",
						"The product does not neutralize user-controllable input before it is placed in a web page."),
				entry(89, "Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')", "Base", "Allowed",
						"The product builds an SQL command using externally-influenced input."),
				entry(564, "SQL Injection: Hibernate", "Variant", "Allowed", "Using Hibernate to execute a dynamic SQL statement."),
				entry(74, "Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')",
						"Class", "Discouraged", "Injection into a downstream component such as SQL or a shell."),
				entry(547, "Use of Hard-coded, Security-relevant Constants", "Base", "Allowed", "The product uses hard-coded constants."),
				entry(22, "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')", "Base", "Allowed",
						"The product uses external input to construct a pathname."),
				entry(352, "Cross-Site Request Forgery (CSRF)", "Compound", "Allowed", "The web application does not verify requests."),
				entry(500, "Old Entry", "Base", "Prohibited", "Gone.")));
		service = new CweCatalogService(store, provider);
	}

	private static CweCatalogMetaEntity loadedMeta() throws Exception {
		CweCatalogMetaEntity row = new CweCatalogMetaEntity();
		row.succeeded("4.20", "2026-04-30", 8, 1_000L, "alice");
		return row;
	}

	private static CweEntry entry(int id, String name, String abstraction, String usage, String description) {
		return new CweEntry(id, name, abstraction, "Simple", "Stable", usage, description, null, List.of());
	}

	@Test
	void findsAnEntryByLabelOrNumberInAnyCase() {
		assertThat(service.find("CWE-79")).map(CweEntry::id).contains(79);
		assertThat(service.find("cwe-89")).map(CweEntry::id).contains(89);
		assertThat(service.find("22")).map(CweEntry::id).contains(22);
		assertThat(service.find("CWE-9999")).isEmpty();
		assertThat(service.find("not a cwe")).isEmpty();
		assertThat(service.find(null)).isEmpty();
	}

	@Test
	void anEntryMitreDiscouragesIsKnownButNotUsable() {
		assertThat(service.isUsable("CWE-79")).isTrue();
		assertThat(service.isUsable("CWE-74")).isFalse();
		assertThat(service.isUsable("CWE-500")).isFalse();
		assertThat(service.isUsable("CWE-9999")).isFalse();
		assertThat(service.find("CWE-74")).isPresent();
	}

	@Test
	void namesAnEntryForTooltips() {
		assertThat(service.name("CWE-89")).startsWith("CWE-89 · Improper Neutralization");
		assertThat(service.name("CWE-9999")).isNull();
	}

	@Test
	void anEmptyCatalogUsesNothingAndKnowsItIsEmpty() throws Exception {
		when(store.meta()).thenReturn(new CweCatalogMetaEntity());
		when(store.all()).thenReturn(List.of());

		assertThat(service.isLoaded()).isFalse();
		assertThat(service.isUsable("CWE-79")).isFalse();
		assertThat(service.shortlist("sql injection", 5)).isEmpty();
	}

	@Test
	void shortlistRanksByWordsInTheNameThenTheDescription() {
		var picks = service.shortlist("AvoidConcatenatedSql builds an SQL command from input", 3);

		assertThat(picks).extracting(CweEntry::id).first().isEqualTo(89);
		assertThat(picks).extracting(CweEntry::id).contains(564);
		assertThat(picks).extracting(CweEntry::id).doesNotContain(74, 500);
	}

	@Test
	void shortlistUnderstandsCommonAbbreviations() {
		assertThat(service.shortlist("reflected XSS in template", 3)).extracting(CweEntry::id).first().isEqualTo(79);
		assertThat(service.shortlist("csrf token missing", 3)).extracting(CweEntry::id).first().isEqualTo(352);
		assertThat(service.shortlist("path traversal in download", 3)).extracting(CweEntry::id).first().isEqualTo(22);
	}

	@Test
	void shortlistSplitsRuleNamesWrittenInCamelCase() {
		assertThat(service.shortlist("AvoidUsingHardCodedIP", 3)).extracting(CweEntry::id).first().isEqualTo(547);
	}

	@Test
	void shortlistIsEmptyWhenNothingMatchesAndIsAlwaysBounded() {
		assertThat(service.shortlist("zzz qqq", 5)).isEmpty();
		assertThat(service.shortlist("injection input web", 1)).hasSize(1);
		assertThat(service.shortlist(null, 5)).isEmpty();
	}

	@Test
	void searchTakesANumberOrWordsAndMayShowDiscouragedEntries() {
		assertThat(service.search("CWE-74", 5)).extracting(CweEntry::id).containsExactly(74);
		assertThat(service.search("79", 5)).extracting(CweEntry::id).containsExactly(79);
		assertThat(service.search("hibernate", 5)).extracting(CweEntry::id).first().isEqualTo(564);
		assertThat(service.search("injection", 10)).extracting(CweEntry::id).contains(74);
	}

	@Test
	void chipTipsNameTheWeaknessAndSayWhatTheCweIsFor() {
		assertThat(service.chipTip("CWE-89", "Primary: used for coverage and reports")).startsWith("CWE-89 · Improper Neutralization")
				.endsWith("\nPrimary: used for coverage and reports");
		assertThat(service.chipTip("CWE-9999", "Secondary")).isEqualTo("Not in the loaded CWE catalog\nSecondary");
	}

	@Test
	void aChipNeedsAttentionOnlyWhenTheCatalogIsLoadedAndDoesNotAllowTheCwe() throws Exception {
		assertThat(service.needsAttention("CWE-79")).isFalse();
		assertThat(service.needsAttention("CWE-74")).as("discouraged by MITRE").isTrue();
		assertThat(service.needsAttention("CWE-9999")).as("not in the catalog").isTrue();

		when(store.meta()).thenReturn(new CweCatalogMetaEntity());
		when(store.all()).thenReturn(List.of());

		assertThat(service.needsAttention("CWE-9999")).as("nothing to check against").isFalse();
		assertThat(service.chipTip("CWE-79", "Primary")).isEqualTo("The CWE catalog is not loaded\nPrimary");
	}

	@Test
	void chipsListThePrimaryFirstThenTheSecondaryOnesAndFlagWhatTheCatalogDoesNotAllow() {
		var chips = service.chipsFor("CWE-89", "CWE-564, CWE-74,CWE-9999");

		assertThat(chips).extracting(CweCatalogService.ChipView::label).containsExactly("CWE-89", "CWE-564", "CWE-74", "CWE-9999");
		assertThat(chips).extracting(CweCatalogService.ChipView::primary).containsExactly(true, false, false, false);
		assertThat(chips).extracting(CweCatalogService.ChipView::warn).containsExactly(false, false, true, true);
		assertThat(chips.get(0).tip()).startsWith("CWE-89 · Improper Neutralization").endsWith("Primary: used for coverage and reports");
		assertThat(chips.get(3).tip()).isEqualTo("Not in the loaded CWE catalog\nSecondary");
		assertThat(service.chipsFor(null, null)).isEmpty();
		assertThat(service.chipsFor(" ", "")).isEmpty();
	}

	@Test
	void splitsAStoredListOfCwesAndToleratesNothing() {
		assertThat(CweCatalogService.split("CWE-564,CWE-943")).containsExactly("CWE-564", "CWE-943");
		assertThat(CweCatalogService.split(" CWE-1 , ,CWE-2 ")).containsExactly("CWE-1", "CWE-2");
		assertThat(CweCatalogService.split(null)).isEmpty();
		assertThat(CweCatalogService.split("")).isEmpty();
	}

	@Test
	void reloadsTheCatalogOnlyWhenTheStoredReleaseChanges() throws Exception {
		service.find("CWE-79");
		service.find("CWE-89");
		verify(store, org.mockito.Mockito.times(1)).all();

		CweCatalogMetaEntity next = new CweCatalogMetaEntity();
		next.succeeded("4.21", "2026-10-01", 8, 2_000L, "bob");
		when(store.meta()).thenReturn(next);
		service.find("CWE-79");

		verify(store, org.mockito.Mockito.times(2)).all();
	}

	@Test
	void statusSaysUpdatingWhileAJobIsQueuedOrRunning() {
		AsyncJobEntity running = new AsyncJobEntity();
		running.setType(AsyncJobType.CWE_CATALOG_REFRESH);
		running.setStatus(AsyncJobStatus.RUNNING);
		when(jobs.getActiveJobs()).thenReturn(List.of(running));

		var status = service.status();

		assertThat(status.state()).isEqualTo("UPDATING");
		assertThat(status.version()).isEqualTo("4.20");
	}

	@Test
	void statusReportsTheLastOutcomeWhenNothingIsRunning() {
		when(jobs.getActiveJobs()).thenReturn(List.of());

		var status = service.status();

		assertThat(status.state()).isEqualTo("OK");
		assertThat(status.count()).isEqualTo(8);
		assertThat(status.by()).isEqualTo("alice");
	}

	@Test
	void requestingARefreshQueuesOneJobAndReportsADuplicate() {
		AsyncJobEntity job = new AsyncJobEntity();
		when(jobs.enqueue(eq(AsyncJobType.CWE_CATALOG_REFRESH), anyString(), eq("cwe-catalog"), eq("alice")))
				.thenReturn(Optional.of(job)).thenReturn(Optional.empty());

		assertThat(service.requestRefresh("alice", false)).isTrue();
		assertThat(service.requestRefresh("alice", true)).isFalse();
	}
}
