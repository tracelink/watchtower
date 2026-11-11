package com.tracelink.appsec.watchtower.core.scan.code;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageRequest;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanResultsService.Kind;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRScanRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.SeverityCounts;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryPullRequestService;

class CodeScanResultsServiceTest {
	@Test
	void secondMixedPageDoesNotSkipInterleavedScanTypes() {
		var prs = mock(PRScanRepository.class);
		var violations = mock(PRViolationRepository.class);
		var repos = mock(RepoScanRepository.class);
		var service = new CodeScanResultsService(prs, violations, repos,
				mock(RepositoryPullRequestService.class));
		var repository = new RepositoryEntity();
		repository.setRepoName("payments-api");
		repository.setApiLabel("bb");
		var prRows = new java.util.ArrayList<PRScanRepository.ResultRow>();
		var repoRows = new java.util.ArrayList<RepoScanEntity>();
		var prKeys = new java.util.ArrayList<PRScanRepository.ResultKey>();
		var repoKeys = new java.util.ArrayList<RepoScanRepository.ResultKey>();
		for (int i = 0; i < 21; i++) {
			var pr = mock(PRScanRepository.ResultRow.class);
			when(pr.getId()).thenReturn((long) i + 1);
			when(pr.getRepoName()).thenReturn("payments-api");
			when(pr.getPrId()).thenReturn(String.valueOf(i + 1));
			when(pr.getEndDate()).thenReturn(200L - i * 2);
			when(pr.getStatus()).thenReturn(ScanStatus.DONE);
			prRows.add(pr);
			var prKey = mock(PRScanRepository.ResultKey.class);
			when(prKey.getId()).thenReturn((long) i + 1);
			when(prKey.getEndDate()).thenReturn(200L - i * 2);
			prKeys.add(prKey);
			var scan = new RepoScanEntity();
			org.springframework.test.util.ReflectionTestUtils.setField(scan, "id", (long) i + 1_000);
			scan.setRepository(repository);
			scan.setBranch("main");
			scan.setStatus(ScanStatus.DONE);
			scan.setEndDate(199L - i * 2);
			scan.setSeverityCounts(SeverityCounts.empty());
			repoRows.add(scan);
			var repoKey = mock(RepoScanRepository.ResultKey.class);
			when(repoKey.getId()).thenReturn(scan.getId());
			when(repoKey.getEndDate()).thenReturn(scan.getEndDate());
			repoKeys.add(repoKey);
		}
		when(prs.count()).thenReturn(21L);
		when(repos.count()).thenReturn(21L);
		when(prs.findResultKeys(PageRequest.of(0, 40))).thenReturn(prKeys);
		when(repos.findResultKeys(PageRequest.of(0, 40))).thenReturn(repoKeys);
		when(prs.findResultRowsByIds(anyList())).thenAnswer(call -> {
			List<Long> ids = call.getArgument(0);
			return prRows.stream().filter(row -> ids.contains(row.getId())).toList();
		});
		when(repos.findResultRowsByIds(anyList())).thenAnswer(call -> {
			List<Long> ids = call.getArgument(0);
			return repoRows.stream().filter(row -> ids.contains(row.getId())).toList();
		});
		var second = service.page(Kind.ALL, 1, null);
		assertEquals(42, second.totalElements());
		assertEquals(21, second.firstElementNumber());
		assertEquals(40, second.lastElementNumber());
		assertEquals(180, second.content().getFirst().getSortTime());
		assertEquals(161, second.content().getLast().getSortTime());
	}

	@Test
	void globalAndPerRepositoryHistoryMergeIndividualScansByCompletion() {
		var prs = mock(PRScanRepository.class);
		var violations = mock(PRViolationRepository.class);
		var repos = mock(RepoScanRepository.class);
		var aliases = mock(RepositoryPullRequestService.class);
		var service = new CodeScanResultsService(prs, violations, repos, aliases);
		var repository = new RepositoryEntity();
		repository.setRepoName("payments-api");
		repository.setApiLabel("bb");
		var repoScan = new RepoScanEntity();
		repoScan.setRepository(repository);
		repoScan.setBranch("main");
		repoScan.setStatus(ScanStatus.DONE);
		repoScan.setStartDate(250);
		repoScan.setEndDate(300);
		repoScan.setSeverityCounts(SeverityCounts.of(List.of(RulePriority.HIGH)));
		var prScan = mock(PRScanRepository.ResultRow.class);
		when(prScan.getId()).thenReturn(42L);
		when(prScan.getRepoName()).thenReturn("payments-api");
		when(prScan.getPrId()).thenReturn("58");
		when(prScan.getEndDate()).thenReturn(200L);
		when(prScan.getStatus()).thenReturn(ScanStatus.DONE);
		var prKey = mock(PRScanRepository.ResultKey.class);
		when(prKey.getId()).thenReturn(42L);
		when(prKey.getEndDate()).thenReturn(200L);
		var repoKey = mock(RepoScanRepository.ResultKey.class);
		when(repoKey.getId()).thenReturn(repoScan.getId());
		when(repoKey.getEndDate()).thenReturn(300L);
		when(prs.count()).thenReturn(1L);
		when(repos.count()).thenReturn(1L);
		when(prs.findResultKeys(PageRequest.of(0, 20))).thenReturn(List.of(prKey));
		when(repos.findResultKeys(PageRequest.of(0, 20))).thenReturn(List.of(repoKey));
		when(prs.findResultRowsByIds(List.of(42L))).thenReturn(List.of(prScan));
		when(repos.findResultRowsByIds(List.of(repoScan.getId()))).thenReturn(List.of(repoScan));
		when(violations.countSeveritiesByScanId(List.of(42L))).thenReturn(List.of());
		when(violations.countMcrByScanId(List.of(42L))).thenReturn(List.of());

		var global = service.page(Kind.ALL, 0, null);
		assertEquals(2, global.totalElements());
		assertEquals(List.of("payments-api@main", "payments-api #58"),
				global.content().stream().map(item -> item.getTarget()).toList());
		assertEquals(1, global.content().getFirst().getFindingCount());

		when(aliases.namesOf("bb", "payments-api")).thenReturn(Set.of("payments-api"));
		when(prs.countResultRowsForRepository("bb", Set.of("payments-api"))).thenReturn(1L);
		when(repos.countByRepositoryId(repository.getId())).thenReturn(1L);
		when(prs.findResultKeysForRepository("bb", Set.of("payments-api"),
				PageRequest.of(0, 20))).thenReturn(List.of(prKey));
		when(repos.findResultKeysForRepository(repository.getId(),
				PageRequest.of(0, 20))).thenReturn(List.of(repoKey));
		assertEquals(global.content().stream().map(item -> item.getTarget()).toList(),
				service.page(Kind.ALL, 0, repository).content().stream()
						.map(item -> item.getTarget()).toList());
	}

	@Test
	void nullAndInformationalSeverityGroupsBothContributeToPrTotal() {
		var prs = mock(PRScanRepository.class);
		var violations = mock(PRViolationRepository.class);
		var repos = mock(RepoScanRepository.class);
		var service = new CodeScanResultsService(prs, violations, repos,
				mock(RepositoryPullRequestService.class));
		var pr = mock(PRScanRepository.ResultRow.class);
		when(pr.getId()).thenReturn(42L);
		when(pr.getStatus()).thenReturn(ScanStatus.DONE);
		when(pr.getEndDate()).thenReturn(200L);
		when(prs.count()).thenReturn(1L);
		when(prs.findResultRows(PageRequest.of(0, 20))).thenReturn(List.of(pr));
		when(violations.countSeveritiesByScanId(List.of(42L))).thenReturn(List.of(
				new Object[] {42L, null, 2L},
				new Object[] {42L, RulePriority.INFORMATIONAL, 3L}));
		var result = service.page(Kind.PR, 0, null);
		assertEquals(5, result.content().getFirst().getFindingCount());
	}
}
