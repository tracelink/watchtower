package com.tracelink.appsec.watchtower.core.assistant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.security.access.AccessDeniedException;

import com.tracelink.appsec.watchtower.core.process.ProcessRunner;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.SourceDownloadLimits;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryRepository;

/** The AI review reads the picked files from one pinned download, masked and cut, and never fails the others for one. */
class AssistantReviewFilesTest {
	@TempDir
	Path dir;
	final String commit = "a".repeat(40);
	AssistantAccess access;
	AssistantSecretFindings secrets;
	IScmApi api;
	RepositoryEntity repo;
	AssistantSourceTools source;

	@BeforeEach
	void setUp() throws Exception {
		access = mock(AssistantAccess.class);
		var repos = mock(RepositoryRepository.class);
		var integrations = mock(ApiIntegrationService.class);
		api = mock(IScmApi.class);
		repo = mock(RepositoryEntity.class);
		when(repo.getId()).thenReturn(42L);
		when(repo.getApiLabel()).thenReturn("fixture");
		when(repo.getRepoName()).thenReturn("example");
		var integration = mock(ApiIntegrationEntity.class);
		when(integration.createApi()).thenReturn(api);
		when(integrations.findByLabel("fixture")).thenReturn(integration);
		secrets = mock(AssistantSecretFindings.class);
		when(secrets.lines(any())).thenReturn(new AssistantSecretFindings.Lines(Map.of()));
		source = new AssistantSourceTools(access, repos, integrations, mock(ProcessRunner.class), secrets, "/trusted/python3", dir.toString());
		doAnswer(invocation -> {
			Path root = invocation.getArgument(2);
			Files.createDirectories(root.resolve("app"));
			Files.writeString(root.resolve("app/Service.java"), "class Service {\n  String q(String id) {\n    return \"select \" + id;\n  }\n}\n");
			Files.writeString(root.resolve("app/Config.java"), "class Config {\n  String key = \"private-value\";\n  int n = 1;\n}\n");
			Files.writeString(root.resolve("app/Long.java"), "int a;\n".repeat(50));
			Files.write(root.resolve("app/Binary.java"), new byte[] { 0, 1, 2, 3 });
			Files.writeString(root.resolve(".env"), "credential=private-value");
			return null;
		}).when(api).downloadSource(eq("example"), eq(commit), any(Path.class), eq(SourceDownloadLimits.ASSISTANT));
	}

	@Test
	void picksAreReadFromOneDownloadWithNumberedBoundedText() throws Exception {
		var files = source.reviewFiles("alice", repo, commit, List.of("app/Service.java", "app/Long.java"), 20, 10_000);

		assertEquals(2, files.size());
		assertEquals("app/Service.java", files.get(0).path());
		assertEquals(5, files.get(0).lines().size());
		assertEquals("    return \"select \" + id;", files.get(0).lines().get(2));
		assertFalse(files.get(0).cut());
		assertTrue(files.get(1).cut(), "a long file is cut and says so");
		assertEquals(20, files.get(1).lines().size());
		assertEquals(50, files.get(1).totalLines());
		verify(api, times(1)).downloadSource(eq("example"), eq(commit), any(Path.class), eq(SourceDownloadLimits.ASSISTANT));
		try (var left = Files.list(dir)) {
			assertEquals(0, left.count(), "the download is deleted");
		}
	}

	@Test
	void linesWhereASecretWasRecordedAreMaskedAndSaidSo() {
		when(secrets.lines(any())).thenReturn(new AssistantSecretFindings.Lines(Map.of("app/Config.java", Map.of(2, "Betterleaks"))));

		var config = source.reviewFiles("alice", repo, commit, List.of("app/Config.java"), 100, 10_000).get(0);

		assertEquals("[REDACTED: secret detected by Betterleaks]", config.lines().get(1));
		assertEquals(java.util.Set.of(2), config.maskedLines());
		assertFalse(String.join("\n", config.lines()).contains("private-value"));
	}

	@Test
	void aFileThatCannotBeReadIsLeftOutWithAReasonAndTheRestAreStillRead() {
		var files = source.reviewFiles("alice", repo, commit, List.of("app/Missing.java", "app/Binary.java", ".env", "../escape.java", "app/Service.java"), 100, 10_000);

		assertEquals(5, files.size());
		for (int i = 0; i < 4; i++) {
			assertFalse(files.get(i).readable(), files.get(i).path());
			assertTrue(files.get(i).lines().isEmpty());
			assertEquals("It could not be read at this commit.", files.get(i).skipped());
		}
		assertTrue(files.get(4).readable());
	}

	@Test
	void everyGrantAndBoundIsCheckedBeforeAnythingIsDownloaded() throws Exception {
		doThrow(new AccessDeniedException("no")).when(access).require("bob", "Assistant Source Read");
		assertThrows(AccessDeniedException.class, () -> source.reviewFiles("bob", repo, commit, List.of("app/Service.java"), 100, 10_000));
		assertThrows(IllegalArgumentException.class, () -> source.reviewFiles("alice", repo, "main", List.of("app/Service.java"), 100, 10_000));
		assertThrows(IllegalArgumentException.class, () -> source.reviewFiles("alice", repo, commit, List.of(), 100, 10_000));
		assertThrows(IllegalArgumentException.class, () -> source.reviewFiles("alice", repo, commit, java.util.Collections.nCopies(AssistantSourceTools.MAX_REVIEW_FILES + 1, "a.java"), 100, 10_000));
		assertThrows(IllegalArgumentException.class, () -> source.reviewFiles("alice", repo, commit, List.of("a.java"), 0, 10_000));
		assertThrows(IllegalArgumentException.class, () -> source.reviewFiles("alice", repo, commit, List.of("a.java"), 100, 0));
		verify(api, times(0)).downloadSource(anyString(), anyString(), any(Path.class), any());
	}
}
