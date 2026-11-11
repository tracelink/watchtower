package com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.BDDMockito;

public class PRBypassAuditServiceTest {

	@Test
	public void testCountsTheLastNinetyDays() {
		Instant now = Instant.parse("2026-10-05T12:00:00Z");
		PullRequestBypassRepository repository = BDDMockito.mock(PullRequestBypassRepository.class);
		long since = now.minus(Duration.ofDays(90)).toEpochMilli();
		List<RepoBypassCount> counts = List.of(new RepoBypassCount("bb", "payments", 3));
		BDDMockito.when(repository.countPerRepositorySince(since)).thenReturn(counts);

		BypassAudit audit = new PRBypassAuditService(repository,
				Clock.fixed(now, ZoneOffset.UTC)).audit();

		Assertions.assertEquals(counts, audit.perRepo());
	}
}
