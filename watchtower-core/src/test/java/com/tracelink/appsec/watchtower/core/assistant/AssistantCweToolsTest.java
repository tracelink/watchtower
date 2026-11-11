package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.JsonNode;
import com.tracelink.appsec.watchtower.core.assistant.tools.CweTools;
import com.tracelink.appsec.watchtower.core.cwe.CweCatalogService;
import com.tracelink.appsec.watchtower.core.cwe.CweEntry;

/** The chat's CWE reference tools: read-only lookups in the local MITRE catalog, behind their own switch. */
class AssistantCweToolsTest {
	static final Set<String> GRANTS = Set.of("Assistant Use", "Ruleset View");
	@TempDir
	Path dir;
	AssistantFixture fx;
	CweCatalogService catalog;
	List<AssistantTool> tools;

	@BeforeEach
	void setup() throws Exception {
		fx = new AssistantFixture(dir, GRANTS);
		fx.tools.setSettings(fx.settings);
		fx.configure(c -> c.putObject("features").putObject("enabled").put("cweReference", true));
		catalog = mock(CweCatalogService.class);
		when(catalog.isLoaded()).thenReturn(true);
		tools = new CweTools(catalog).tools();
		tools.forEach(fx.tools::register);
	}

	@AfterEach
	void close() {
		fx.close();
	}

	static CweEntry entry(int id, String name, String usage, String description, List<Integer> parents) {
		return new CweEntry(id, name, "Base", "Simple", "Stable", usage, description, "High", parents);
	}

	JsonNode call(String name, String args) {
		return fx.tools.invoke("alice", name, args, 16384, AssistantState.TOOL_VERSION, "turn-1").path("data");
	}

	@Test
	void twoReadOnlyToolsBehindTheCweReferenceSwitch() {
		assertEquals(Set.of("search_cwe", "get_cwe"), new TreeSet<>(tools.stream().map(AssistantTool::name).toList()));
		for (AssistantTool tool : tools) {
			assertEquals(AssistantTool.Effect.EVIDENCE_READ, tool.effect(), tool.name());
			assertEquals(AssistantFeature.CWE_REFERENCE, tool.feature(), tool.name());
		}
		assertTrue(fx.tools.schemas("alice").toString().contains("\"search_cwe\""));
	}

	@Test
	void theToolsAreOffUntilTheSwitchIsOn() throws Exception {
		fx.configure(c -> c.putObject("features").putObject("enabled").put("cweReference", false));

		assertFalse(fx.tools.schemas("alice").toString().contains("\"search_cwe\""));
		assertThrows(IllegalArgumentException.class, () -> call("search_cwe", "{\"query\":\"sql injection\"}"),
				"a call from an older chat is refused too");
	}

	@Test
	void searchReturnsAShortListWithTheCatalogFlaggedAsUntrustedText() {
		when(catalog.search(eq("sql injection"), anyInt()))
				.thenReturn(List.of(entry(89, "SQL Injection", "Allowed", "x".repeat(600), List.of(74)),
						entry(74, "Injection", "Discouraged", "Class.", List.of())));

		JsonNode data = call("search_cwe", "{\"query\":\"sql injection\"}");

		assertEquals(2, data.path("results").size());
		JsonNode first = data.path("results").get(0);
		assertEquals("CWE-89", first.path("cwe").asText());
		assertEquals("SQL Injection", first.path("name").asText());
		assertEquals("Allowed", first.path("usage").asText());
		assertTrue(first.path("summary").asText().length() <= 240, "descriptions are cut");
		assertEquals("Discouraged", data.path("results").get(1).path("usage").asText());
		assertTrue(data.path("data_is_untrusted").asBoolean(), "catalog text is data, never instructions");
	}

	@Test
	void searchIsBoundedAndRejectsAnEmptyOrHugeQuery() {
		when(catalog.search(anyString(), anyInt())).thenReturn(List.of());

		call("search_cwe", "{\"query\":\"path traversal\"}");

		verify(catalog).search(eq("path traversal"), intThat(limit -> limit >= 1 && limit <= 10));
		assertThrows(IllegalArgumentException.class, () -> call("search_cwe", "{\"query\":\"  \"}"));
		assertThrows(IllegalArgumentException.class, () -> call("search_cwe", "{\"query\":\"" + "a".repeat(300) + "\"}"));
	}

	@Test
	void getReturnsOneEntryWithItsParentsNamed() {
		when(catalog.find("CWE-79")).thenReturn(Optional.of(entry(79, "Cross-site Scripting", "Allowed", "Script in a page.", List.of(74))));
		when(catalog.find("74")).thenReturn(Optional.of(entry(74, "Injection", "Discouraged", "Class.", List.of())));

		JsonNode data = call("get_cwe", "{\"cwe\":\"CWE-79\"}");

		assertEquals("CWE-79", data.path("cwe").asText());
		assertEquals("Script in a page.", data.path("description").asText());
		assertEquals("CWE-74", data.path("parents").get(0).path("cwe").asText());
		assertEquals("Injection", data.path("parents").get(0).path("name").asText());
		assertTrue(data.path("data_is_untrusted").asBoolean());
	}

	@Test
	void anUnknownCweIsReportedAsNotAvailable() {
		when(catalog.find("CWE-99999")).thenReturn(Optional.empty());

		assertThrows(IllegalArgumentException.class, () -> call("get_cwe", "{\"cwe\":\"CWE-99999\"}"));
	}

	@Test
	void anEmptyCatalogSaysHowToLoadItInsteadOfInventingAnswers() {
		when(catalog.isLoaded()).thenReturn(false);

		JsonNode data = call("search_cwe", "{\"query\":\"sql injection\"}");

		assertEquals(0, data.path("results").size());
		assertTrue(data.path("note").asText().toLowerCase().contains("not loaded"));
		verify(catalog, never()).search(anyString(), anyInt());
	}
}
