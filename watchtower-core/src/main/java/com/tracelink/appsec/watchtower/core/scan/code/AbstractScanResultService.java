package com.tracelink.appsec.watchtower.core.scan.code;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.LongSummaryStatistics;
import java.util.stream.Collectors;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.domain.Sort.Direction;

/**
 * The Scan Result Service is used to get information about completed Scans including Violations.
 *
 * @author csmith
 * @param <S> a type describing this scan result's associated Scan
 * @param <V> a type describing this scan result's associated Violation
 */
public abstract class AbstractScanResultService<S extends AbstractScanEntity<?, ?>, V extends AbstractViolationEntity<S>> {

	private final IScanRepository<S> scanRepo;
	private final IViolationRepository<V> vioRepo;
	private LocalDate oldestScanDate;

	protected AbstractScanResultService(IScanRepository<S> scanRepo,
			IViolationRepository<V> vioRepo) {
		this.scanRepo = scanRepo;
		this.vioRepo = vioRepo;
	}

	/**
	 * retrieve the last N scans from a backend database
	 *
	 * @param lastNum (up to) the last number of scans to retrieve
	 * @return a list of up to N number of recent scans
	 */
	public List<S> getLastScans(int lastNum) {
		List<S> infoList = new ArrayList<>(lastNum);
		Page<S> entities = scanRepo
				.findAll(PageRequest.of(0, lastNum, Sort.by(Direction.DESC, "endDate")));
		infoList.addAll(entities.getContent());
		return infoList;
	}


	/**
	 * Counts the total number of scans performed
	 *
	 * @return number of scans
	 */
	public long countScans() {
		return scanRepo.count();
	}

	/**
	 * Counts the number of violations that have been found, only considering those which are new
	 * violations
	 *
	 * @return number of violations found
	 */
	public long countViolations() {
		return vioRepo.count();
	}

	/**
	 * Gets an iterator to iterate over all pages of scans in the {@code scanRepo} with an end date
	 * between the given start and end times.
	 *
	 * @param startMillis earliest date of scans to iterate through
	 * @param endMillis   latest date of scans to iterate through
	 * @return iterator for pages of scans in the database
	 */
	public Iterator<Page<AbstractScanEntity<?, ?>>> scanIteratorBetweenDates(long startMillis,
			long endMillis) {
		return new Iterator<Page<AbstractScanEntity<?, ?>>>() {
			private Page<S> page;

			@Override
			public boolean hasNext() {
				return page == null || page.hasNext();
			}

			@Override
			public Page<AbstractScanEntity<?, ?>> next() {
				Pageable pageable = page == null ? PageRequest.of(0, 1000)
						: page.nextPageable();
				page = scanRepo.findAllByEndDateBetween(startMillis, endMillis,
						pageable);
				return (Page<AbstractScanEntity<?, ?>>) page;
			}
		};
	}

	/**
	 * Finds the oldest scan in the database and returns the date it was scanned. If no scans in
	 * database, returns the current date.
	 *
	 * @return local date object representing the day the oldest scan was completed, or the current
	 * date if there are no scans
	 */
	public LocalDate getOldestScanDate() {
		if (oldestScanDate == null) {
			S oldest = scanRepo.findFirstByOrderByEndDateAsc();
			oldestScanDate = oldest != null ? oldest.getEndDate().toLocalDate() : LocalDate.now();
		}
		return oldestScanDate;
	}

	/**
	 * Get the average time (in milliseconds) all scans took to run, from starting (not just
	 * queuing) to ending (report made).
	 *
	 * @return the average time in milliseconds to scan for this container type
	 */
	public double getAverageTime() {
		int page = 0;
		Page<S> scanPage;
		LongSummaryStatistics stats = new LongSummaryStatistics();
		do {
			scanPage = scanRepo.findAll(PageRequest.of(page, 1000));
			stats.combine(scanPage.stream()
					.filter(s -> s.getStartDateMillis() > 0 && s.getEndDateMillis() > 0)
					.collect(Collectors.summarizingLong(
							se -> se.getEndDateMillis() - se.getStartDateMillis())));
			page++;
		} while (!scanPage.isLast());

		return stats.getAverage();
	}

}
