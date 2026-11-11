package com.tracelink.appsec.watchtower.core.mvc;

import java.util.List;
import java.util.function.Function;
import java.util.stream.IntStream;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Slice;

/**
 * One page of mapped results, plus whether a further page exists. Used by the result-viewer
 * controllers/templates to drive Previous/Next pagination without leaking Spring Data's
 * {@linkplain Slice}/{@linkplain org.springframework.data.domain.Page} types past the service
 * layer (IMPROVEMENT_PLAN.md item 9.3: {@code Slice.hasNext()} was already available
 * server-side but was never wired to disable the "Next" control at the last page).
 *
 * @param <T> the mapped result type shown to the view
 */
public record PagedResult<T>(List<T> content, int pageNumber, int pageSize, long totalElements,
		int totalPages) {

	private static final int PAGE_WINDOW_SIZE = 5;

	/**
	 * Compatibility constructor for callers that only know whether another slice exists.
	 * Exact totals are available when callers use {@link #of(Page, Function)}.
	 */
	public PagedResult(List<T> content, boolean hasNext) {
		this(content, 0, content.size(), content.size() + (hasNext ? 1L : 0L),
				hasNext ? 2 : (content.isEmpty() ? 0 : 1));
	}

	public boolean hasNext() {
		return pageNumber + 1 < totalPages;
	}

	public boolean hasPrevious() {
		return pageNumber > 0 && totalPages > 0;
	}

	public long firstElementNumber() {
		return content.isEmpty() ? 0 : (long) pageNumber * pageSize + 1;
	}

	public long lastElementNumber() {
		return content.isEmpty() ? 0 : firstElementNumber() + content.size() - 1;
	}

	/**
	 * One-based page numbers for a bounded, centered paginator window.
	 */
	public List<Integer> pageWindow() {
		if (totalPages == 0) {
			return List.of();
		}
		int start = Math.max(1, pageNumber + 1 - PAGE_WINDOW_SIZE / 2);
		start = Math.min(start, Math.max(1, totalPages - PAGE_WINDOW_SIZE + 1));
		int end = Math.min(totalPages, start + PAGE_WINDOW_SIZE - 1);
		return IntStream.rangeClosed(start, end).boxed().collect(Collectors.toList());
	}

	/**
	 * Map a {@linkplain Slice} of entities to a {@linkplain PagedResult} of view results,
	 * carrying {@code slice.hasNext()} through.
	 *
	 * @param slice  the Slice/Page returned by a repository query
	 * @param mapper maps one entity to its view result
	 * @param <S>    the entity type
	 * @param <T>    the mapped result type
	 * @return a {@linkplain PagedResult} with the mapped content and {@code hasNext} flag
	 */
	public static <S, T> PagedResult<T> of(Slice<S> slice, Function<S, T> mapper) {
		List<T> mapped = slice.getContent().stream().map(mapper).collect(Collectors.toList());
		long knownElements = slice.getPageable().getOffset() + mapped.size();
		long estimatedTotal = knownElements + (slice.hasNext() ? 1 : 0);
		int estimatedPages = slice.getSize() == 0 ? 0
				: (int) Math.ceil((double) estimatedTotal / slice.getSize());
		return new PagedResult<>(mapped, slice.getNumber(), slice.getSize(), estimatedTotal,
				estimatedPages);
	}

	/** Map an exact Spring Data page without leaking it into the web layer. */
	public static <S, T> PagedResult<T> of(Page<S> page, Function<S, T> mapper) {
		List<T> mapped = page.getContent().stream().map(mapper).collect(Collectors.toList());
		return new PagedResult<>(mapped, page.getNumber(), page.getSize(), page.getTotalElements(),
				page.getTotalPages());
	}
}
