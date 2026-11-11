package com.tracelink.appsec.watchtower.core.scan.image.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;
import com.tracelink.appsec.watchtower.core.scan.image.report.ImageScanViolation;
import com.tracelink.appsec.watchtower.core.scan.image.repository.AdvisoryRepository;

/**
 * Service used to CRUD Advisory Entities
 * 
 * @author csmith
 *
 */
@Service
public class ImageAdvisoryService {

	private static final java.util.Set<String> SORTS = java.util.Set.of("score", "name");
	private static final int MAX_SEARCH = 200;
	private static final int MAX_PAGE_SIZE = 100;
	private static final double MAX_SCORE = 10;

	private final AdvisoryRepository advisoryRepo;

	public ImageAdvisoryService(@Autowired AdvisoryRepository advisoryRepo) {
		this.advisoryRepo = advisoryRepo;
	}

	public AdvisoryEntity getOrCreateAdvisory(ImageScanViolation sv) {
		AdvisoryEntity advisory = findByName(sv.getFindingName());
		if (advisory == null) {
			advisory = new AdvisoryEntity();
			advisory.setAdvisoryName(sv.getFindingName());
			advisory.setDescription(sv.getDescription());
			advisory.setPackageName(sv.getPackageName());
			advisory.setScore(sv.getScore());
			advisory.setUri(sv.getUri());
			advisory.setVector(sv.getVector());
			advisoryRepo.save(advisory);
		}
		return advisory;
	}

	public AdvisoryEntity findByName(String name) {
		return advisoryRepo.findByAdvisoryName(name);
	}

	public List<AdvisoryEntity> getAllAdvisories() {
		return advisoryRepo.findAll();
	}

	/** One page of advisories, plus the total matching the search and score filter. */
	public record AdvisoryPage(List<AdvisoryEntity> advisories, long total, int page, int size) {
	}

	/**
	 * Searches advisory identifiers and packages, keeps those scoring at least {@code minScore}
	 * (unscored ones only when no minimum is set), sorts by highest score or by name, and loads
	 * full rows for the requested page only. Scores are stored as text, so they are compared here.
	 */
	public AdvisoryPage search(String search, double minScore, String sort, int page, int size) {
		String text = search == null ? "" : search.strip().toLowerCase(java.util.Locale.ROOT);
		if (text.length() > MAX_SEARCH || !SORTS.contains(sort) || minScore < 0 || minScore > MAX_SCORE
				|| page < 0 || size < 1 || size > MAX_PAGE_SIZE || (long) page * size > Integer.MAX_VALUE) {
			throw new IllegalArgumentException("Check the search, score, sort and page");
		}
		String pattern = "%" + text.replace("!", "!!").replace("%", "!%").replace("_", "!_") + "%";
		java.util.Comparator<AdvisoryRepository.AdvisorySummary> byName = java.util.Comparator.comparing(
				summary -> java.util.Objects.toString(summary.getAdvisoryName(), ""));
		java.util.Comparator<AdvisoryRepository.AdvisorySummary> order = "name".equals(sort) ? byName
				: java.util.Comparator.<AdvisoryRepository.AdvisorySummary>comparingDouble(
						summary -> -score(summary.getScore()).orElse(-1.0)).thenComparing(byName);
		List<AdvisoryRepository.AdvisorySummary> matching = advisoryRepo.searchSummaries(pattern).stream()
				.filter(summary -> minScore == 0 || score(summary.getScore()).orElse(-1.0) >= minScore)
				.sorted(order).toList();
		List<AdvisoryRepository.AdvisorySummary> pageRows = matching.stream().skip((long) page * size).limit(size).toList();
		// Advisory names are unique, so they restore the sorted order after loading by id.
		java.util.Map<String, AdvisoryEntity> rows = new java.util.HashMap<>();
		advisoryRepo.findAllById(pageRows.stream().map(AdvisoryRepository.AdvisorySummary::getId).toList())
				.forEach(row -> rows.put(row.getAdvisoryName(), row));
		List<AdvisoryEntity> advisories = pageRows.stream().map(summary -> rows.get(summary.getAdvisoryName()))
				.filter(java.util.Objects::nonNull).toList();
		return new AdvisoryPage(advisories, matching.size(), page, size);
	}

	private static java.util.OptionalDouble score(String value) {
		try {
			return value == null ? java.util.OptionalDouble.empty()
					: java.util.OptionalDouble.of(Double.parseDouble(value.strip()));
		} catch (NumberFormatException notScored) {
			return java.util.OptionalDouble.empty();
		}
	}

	public long getTotalNumberAdvisories() {
		return advisoryRepo.count();
	}

}
