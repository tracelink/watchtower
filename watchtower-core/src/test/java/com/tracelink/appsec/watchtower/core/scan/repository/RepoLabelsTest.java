package com.tracelink.appsec.watchtower.core.scan.repository;

import java.util.Collections;
import java.util.List;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class RepoLabelsTest {

	@Test
	public void formatNormalisesSortsAndDedupes() {
		Assertions.assertEquals(",payments,pci,",
				RepoLabels.format(List.of(" PCI ", "payments", "pci", "")));
	}

	@Test
	public void formatOfNothingIsNull() {
		Assertions.assertNull(RepoLabels.format(null));
		Assertions.assertNull(RepoLabels.format(Collections.emptyList()));
		Assertions.assertNull(RepoLabels.format(List.of(" ", "")));
	}

	@Test
	public void formatRejectsBadLabelsAndTooMany() {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> RepoLabels.format(List.of("has space")));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> RepoLabels.format(List.of("-leading")));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> RepoLabels.format(List.of("a,b")));
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> RepoLabels.format(List.of("x".repeat(33))));
		List<String> eleven = IntStream.range(0, 11).mapToObj(i -> "l" + i).toList();
		Assertions.assertThrows(IllegalArgumentException.class, () -> RepoLabels.format(eleven));
	}

	@Test
	public void parseAndSplitRoundTrip() {
		Assertions.assertEquals(List.of("a", "b"), RepoLabels.parse(",b,a,"));
		Assertions.assertEquals(List.of(), RepoLabels.parse(null));
		Assertions.assertEquals(List.of("pci", "payments", "core"),
				RepoLabels.split(" pci, payments  core "));
		Assertions.assertEquals(List.of(), RepoLabels.split("  "));
	}

	@Test
	public void likePatternMatchesOneLabelExactly() {
		Assertions.assertEquals("%,pci,%", RepoLabels.likePattern("PCI"));
	}

	@Test
	public void entityRejectsUnknownCriticality() {
		RepositoryEntity repo = new RepositoryEntity();
		Assertions.assertEquals(RepoCriticality.NORMAL.getLevel(), repo.getCriticality());
		repo.setCriticality(1);
		Assertions.assertEquals(1, repo.getCriticality());
		Assertions.assertThrows(IllegalArgumentException.class, () -> repo.setCriticality(5));
	}
}
