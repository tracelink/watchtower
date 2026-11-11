package com.tracelink.appsec.watchtower.core.mvc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

class PagedResultTest {

	@Test
	void mapsExactPageMetadataAndCompactWindow() {
		PageImpl<Integer> page = new PageImpl<>(List.of(31, 32, 33, 34, 35, 36, 37, 38, 39, 40),
				PageRequest.of(3, 10), 87);

		PagedResult<String> result = PagedResult.of(page, String::valueOf);

		assertEquals(List.of("31", "32", "33", "34", "35", "36", "37", "38", "39", "40"),
				result.content());
		assertEquals(3, result.pageNumber());
		assertEquals(10, result.pageSize());
		assertEquals(87, result.totalElements());
		assertEquals(9, result.totalPages());
		assertEquals(List.of(2, 3, 4, 5, 6), result.pageWindow());
		assertTrue(result.hasNext());
		assertTrue(result.hasPrevious());
		assertEquals(31, result.firstElementNumber());
		assertEquals(40, result.lastElementNumber());
	}

	@Test
	void emptyResultUsesStableZeroRange() {
		PagedResult<String> result = PagedResult.of(
				new PageImpl<>(List.of(), PageRequest.of(0, 10), 0), String::valueOf);

		assertEquals(0, result.firstElementNumber());
		assertEquals(0, result.lastElementNumber());
		assertTrue(result.pageWindow().isEmpty());
		assertFalse(result.hasPrevious());
		assertFalse(result.hasNext());
	}
}
