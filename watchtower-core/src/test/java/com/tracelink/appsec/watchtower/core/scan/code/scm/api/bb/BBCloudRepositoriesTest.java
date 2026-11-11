package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.BDDMockito;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.tracelink.appsec.watchtower.core.WireMockExtension;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmBranch;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.ScmRepository;

import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;

public class BBCloudRepositoriesTest {

	@RegisterExtension
	public WireMockExtension wireMock =
			new WireMockExtension(WireMockConfiguration.wireMockConfig().dynamicPort());

	private BBCloudIntegrationEntity entity;

	private BBCloudRepositories repositories;

	@BeforeEach
	public void setup() {
		wireMock.resetMappings();
		entity = BDDMockito.mock(BBCloudIntegrationEntity.class);
		BDDMockito.when(entity.getUser()).thenReturn("user");
		BDDMockito.when(entity.getAuth()).thenReturn("token");
		BDDMockito.when(entity.getWorkspace()).thenReturn("ws");
		BDDMockito.when(entity.makeApiWorkspaceUrl())
				.thenReturn(wireMock.baseUrl() + "/repositories/ws");
		BDDMockito.when(entity.makeApiRepoUrl(BDDMockito.anyString()))
				.thenAnswer(i -> wireMock.baseUrl() + "/repositories/ws/" + i.getArgument(0));
		repositories = new BBCloudRepositories(entity);
	}

	private static JSONObject repo(String slug, String updatedOn) {
		JSONObject repo = new JSONObject().put("slug", slug)
				.put("project", new JSONObject().put("key", "PAY"))
				.put("mainbranch", new JSONObject().put("name", "main"))
				.put("size", 2048).put("language", "java");
		return updatedOn == null ? repo : repo.put("updated_on", updatedOn);
	}

	private static JSONObject branch(String name, String hash, String date) {
		JSONObject target = new JSONObject().put("hash", hash);
		if (date != null) {
			target.put("date", date);
		}
		return new JSONObject().put("name", name).put("target", target);
	}

	private static String page(JSONArray values, String next) {
		JSONObject body = new JSONObject().put("values", values);
		return (next == null ? body : body.put("next", next)).toString();
	}

	@Test
	public void listFollowsNextAndRequestsOnlyNeededFields() {
		String next = wireMock.baseUrl() + "/repositories/ws?page=2";
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws"))
				.withQueryParam("fields", WireMock.containing("values.slug"))
				.withQueryParam("pagelen", WireMock.equalTo("100"))
				.willReturn(WireMock.okJson(page(new JSONArray()
						.put(repo("a", "2026-10-01T10:00:00.123456+00:00")), next))));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws"))
				.withQueryParam("page", WireMock.equalTo("2"))
				.willReturn(WireMock.okJson(page(new JSONArray().put(repo("b", "bad-date")),
						null))));

		List<List<ScmRepository>> pages = new ArrayList<>();
		boolean complete = repositories.list(pages::add);

		Assertions.assertTrue(complete);
		Assertions.assertEquals(2, pages.size());
		ScmRepository first = pages.get(0).get(0);
		Assertions.assertEquals("a", first.slug());
		Assertions.assertEquals("PAY", first.projectKey());
		Assertions.assertEquals("main", first.defaultBranch());
		Assertions.assertEquals(1790848800123L, first.updatedOn());
		Assertions.assertEquals(2048, first.sizeBytes());
		Assertions.assertEquals("java", first.language());
		Assertions.assertEquals(0, pages.get(1).get(0).updatedOn());
	}

	@Test
	public void listReportsIncompleteWhenAPageFails() {
		String next = wireMock.baseUrl() + "/repositories/ws?page=2";
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws"))
				.withQueryParam("pagelen", WireMock.equalTo("100"))
				.willReturn(WireMock.okJson(page(new JSONArray().put(repo("a", null)), next))));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws"))
				.withQueryParam("page", WireMock.equalTo("2"))
				.willReturn(WireMock.aResponse().withStatus(500)));

		List<List<ScmRepository>> pages = new ArrayList<>();

		Assertions.assertFalse(repositories.list(pages::add));
		Assertions.assertEquals(1, pages.size());
	}

	@Test
	public void getReadsOneRepositoryWithOnlyTheNeededFields() {
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws/payments-api"))
				.withQueryParam("fields", WireMock.equalTo(
						"slug,project.key,mainbranch.name,updated_on,size,language"))
				.willReturn(WireMock.okJson(repo("payments-api",
						"2026-10-01T10:00:00.123456+00:00").toString())));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws/missing"))
				.willReturn(WireMock.aResponse().withStatus(404)));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws/broken"))
				.willReturn(WireMock.aResponse().withStatus(500)));

		Optional<ScmRepository> found = repositories.getRepository("payments-api");

		Assertions.assertTrue(found.isPresent());
		Assertions.assertEquals("PAY", found.get().projectKey());
		Assertions.assertEquals("main", found.get().defaultBranch());
		Assertions.assertEquals(1790848800123L, found.get().updatedOn());
		Assertions.assertTrue(repositories.getRepository("missing").isEmpty());
		Assertions.assertTrue(repositories.getRepository("broken").isEmpty());
	}

	@Test
	public void listSkipsEntriesWithoutSlug() {
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws"))
				.willReturn(WireMock.okJson(page(new JSONArray()
						.put(new JSONObject().put("size", 1)).put(repo("ok", null)), null))));

		List<ScmRepository> all = new ArrayList<>();

		Assertions.assertTrue(repositories.list(all::addAll));
		Assertions.assertEquals(1, all.size());
		Assertions.assertEquals("ok", all.get(0).slug());
		Assertions.assertEquals(0, all.get(0).updatedOn());
	}

	@Test
	public void getBranchUsesExactQueryAndEscapesQuotes() {
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws/repo/refs/branches"))
				.withQueryParam("q", WireMock.equalTo("name = \"release/\\\"1\\\"\""))
				.willReturn(WireMock.okJson(page(new JSONArray().put(
						branch("release/\"1\"", "abc123", "2026-09-30T00:00:00+00:00")), null))));

		Optional<ScmBranch> found = repositories.getBranch("repo", "release/\"1\"");

		Assertions.assertTrue(found.isPresent());
		Assertions.assertEquals("abc123", found.get().commitHash());
		Assertions.assertEquals(1790726400000L, found.get().commitDate());
	}

	@Test
	public void getBranchEmptyWhenMissingBlankOrError() {
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws/repo/refs/branches"))
				.willReturn(WireMock.okJson(page(new JSONArray(), null))));
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws/gone/refs/branches"))
				.willReturn(WireMock.aResponse().withStatus(404)));

		Assertions.assertTrue(repositories.getBranch("repo", "nope").isEmpty());
		Assertions.assertTrue(repositories.getBranch("repo", " ").isEmpty());
		Assertions.assertTrue(repositories.getBranch("gone", "main").isEmpty());
	}

	@Test
	public void listBranchesFiltersSortsAndCapsAtLimit() {
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws/repo/refs/branches"))
				.withQueryParam("q", WireMock.equalTo("name ~ \"release\""))
				.withQueryParam("sort", WireMock.equalTo("-target.date"))
				.willReturn(WireMock.okJson(page(new JSONArray()
						.put(branch("release/2", "h2", null))
						.put(branch("release/1", "h1", null))
						.put(new JSONObject().put("name", "no-target")), null))));

		List<ScmBranch> branches = repositories.listBranches("repo", "release", 1);

		Assertions.assertEquals(1, branches.size());
		Assertions.assertEquals("release/2", branches.get(0).name());
		Assertions.assertTrue(repositories.listBranches("repo", "release", 0).isEmpty());
	}

	@Test
	public void listBranchesEmptyOnError() {
		WireMock.stubFor(WireMock.get(WireMock.urlPathEqualTo("/repositories/ws/repo/refs/branches"))
				.willReturn(WireMock.aResponse().withStatus(403)));

		Assertions.assertTrue(repositories.listBranches("repo", "", 5).isEmpty());
	}

	@Test
	public void getFileContentReturnsNullOnErrorOrOversize() {
		BDDMockito.when(entity.makeSourceFileUrl("repo", "abc", "a.txt"))
				.thenReturn(wireMock.baseUrl() + "/src/abc/a.txt");
		BDDMockito.when(entity.makeSourceFileUrl("repo", "abc", "big.txt"))
				.thenReturn(wireMock.baseUrl() + "/src/abc/big.txt");
		BDDMockito.when(entity.makeSourceFileUrl("repo", "abc", "gone.txt"))
				.thenReturn(wireMock.baseUrl() + "/src/abc/gone.txt");
		WireMock.stubFor(WireMock.get("/src/abc/a.txt")
				.willReturn(WireMock.aResponse().withStatus(200).withBody("line1\nline2")));
		WireMock.stubFor(WireMock.get("/src/abc/big.txt").willReturn(WireMock.aResponse()
				.withStatus(200)
				.withBody(new byte[BBCloudRepositories.MAX_DISPLAY_FILE_BYTES + 1])));
		WireMock.stubFor(WireMock.get("/src/abc/gone.txt")
				.willReturn(WireMock.aResponse().withStatus(404)));

		Assertions.assertEquals("line1\nline2",
				repositories.getFileContent("repo", "abc", "a.txt"));
		Assertions.assertNull(repositories.getFileContent("repo", "abc", "big.txt"));
		Assertions.assertNull(repositories.getFileContent("repo", "abc", "gone.txt"));
	}

	@Test
	public void fetchFileSaysWhyAFileCannotBeShown() {
		for (String name : new String[] {"ok.txt", "big.txt", "gone.txt", "denied.txt", "broken.txt"}) {
			BDDMockito.when(entity.makeSourceFileUrl("repo", "abc", name))
					.thenReturn(wireMock.baseUrl() + "/src/abc/" + name);
		}
		WireMock.stubFor(WireMock.get("/src/abc/ok.txt")
				.willReturn(WireMock.aResponse().withStatus(200).withBody("fine")));
		// Closing after the large body keeps its bytes from leaking into the next test's response
		WireMock.stubFor(WireMock.get("/src/abc/big.txt").willReturn(WireMock.aResponse()
				.withStatus(200).withHeader("Connection", "close")
				.withBody(new byte[BBCloudRepositories.MAX_DISPLAY_FILE_BYTES + 1])));
		WireMock.stubFor(WireMock.get("/src/abc/gone.txt").willReturn(WireMock.aResponse().withStatus(404)));
		WireMock.stubFor(WireMock.get("/src/abc/denied.txt").willReturn(WireMock.aResponse().withStatus(403)));
		WireMock.stubFor(WireMock.get("/src/abc/broken.txt").willReturn(WireMock.aResponse().withStatus(500)));

		Assertions.assertTrue(repositories.fetchFile("repo", "abc", "ok.txt").isFound());
		Assertions.assertTrue(repositories.fetchFile("repo", "abc", "big.txt").reason()
				.contains("larger than 2 MB"));
		Assertions.assertTrue(repositories.fetchFile("repo", "abc", "gone.txt").reason()
				.contains("deleted or renamed"));
		Assertions.assertTrue(repositories.fetchFile("repo", "abc", "denied.txt").reason()
				.contains("cannot read this repository"));
		Assertions.assertTrue(repositories.fetchFile("repo", "abc", "broken.txt").reason()
				.contains("HTTP 500"));
	}

	@Test
	public void escapeQueryValueEscapesBackslashBeforeQuote() {
		Assertions.assertEquals("a\\\\b\\\"c", BBCloudRepositories.escapeQueryValue("a\\b\"c"));
	}
}
