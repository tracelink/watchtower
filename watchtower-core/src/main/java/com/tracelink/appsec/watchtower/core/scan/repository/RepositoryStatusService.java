package com.tracelink.appsec.watchtower.core.scan.repository;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.scan.ScanType;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity;

/**
 * Works out each repository's one status chip ({@link RepoStatus}) from its row, and turns an
 * inventory filter into a query. The only extra read is the set of integration names, cached
 * for a minute.
 *
 * @author Watchtower
 */
@Service
public class RepositoryStatusService {

	static final long LABEL_CACHE_MILLIS = 60_000L;

	private static final long DAY_MILLIS = Duration.ofDays(1).toMillis();

	private static final char LIKE_ESCAPE = '\\';

	private final ApiIntegrationService integrations;

	private final int inactiveDays;

	private final Clock clock;

	private volatile List<Live> live;

	private volatile long labelsLoadedAt;

	/** An integration that exists now: its name and what it scans. */
	private record Live(String label, ScanType type) {
	}

	@Autowired
	public RepositoryStatusService(ApiIntegrationService integrations,
			@Value("${watchtower.repositories.inactive-days:30}") int inactiveDays) {
		this(integrations, inactiveDays, Clock.systemUTC());
	}

	RepositoryStatusService(ApiIntegrationService integrations, int inactiveDays, Clock clock) {
		this.integrations = integrations;
		this.inactiveDays = Math.max(1, inactiveDays);
		this.clock = clock;
	}

	public int getInactiveDays() {
		return inactiveDays;
	}

	/**
	 * @return the names of the integrations that exist now (cached for a minute)
	 */
	public Set<String> integrationLabels() {
		return liveIntegrations().stream().map(Live::label)
				.collect(Collectors.toUnmodifiableSet());
	}

	/**
	 * @param type the scan type
	 * @return the names of the integrations of that type that exist now: for code
	 *         repositories the source code integrations, never a registry's (cached for a minute)
	 */
	public Set<String> integrationLabels(ScanType type) {
		return liveIntegrations().stream().filter(i -> type.equals(i.type())).map(Live::label)
				.collect(Collectors.toUnmodifiableSet());
	}

	private List<Live> liveIntegrations() {
		long now = clock.millis();
		List<Live> current = live;
		if (current == null || now - labelsLoadedAt > LABEL_CACHE_MILLIS) {
			current = integrations.getAllSettings().stream()
					.filter(i -> i.getApiLabel() != null)
					.map(i -> new Live(i.getApiLabel(), i.getScanType())).toList();
			live = current;
			labelsLoadedAt = now;
		}
		return current;
	}

	/** Forgets the cached integration names, after an integration is added or deleted. */
	public void forgetIntegrations() {
		live = null;
	}

	/**
	 * @return true if the integration this repository came from was deleted. Names compare
	 *         ignoring case, as the database (and so every tab and query) compares them.
	 */
	public boolean isOrphaned(String apiLabel) {
		return apiLabel == null
				|| integrationLabels().stream().noneMatch(apiLabel::equalsIgnoreCase);
	}

	/** @return epoch millis before which a pull request counts as not recent */
	public long inactiveBefore() {
		return clock.millis() - inactiveDays * DAY_MILLIS;
	}

	/**
	 * @return the repository's status; the first matching state wins
	 */
	public RepoStatus statusOf(RepositoryEntity repo) {
		if (isOrphaned(repo.getApiLabel())) {
			return RepoStatus.ORPHANED;
		}
		if (!repo.isEnabled()) {
			return RepoStatus.GONE;
		}
		if (repo.isScanningPaused()) {
			return RepoStatus.PAUSED;
		}
		long lastPr = repo.getLastReviewedDate();
		return lastPr > 0 && lastPr < inactiveBefore() ? RepoStatus.INACTIVE : RepoStatus.ACTIVE;
	}

	/**
	 * @return one sentence saying why the repository has its status, for the chip's popover
	 */
	public String reason(RepositoryEntity repo) {
		long lastPr = repo.getLastReviewedDate();
		if (repo.getScanType() instanceof com.tracelink.appsec.watchtower.core.scan.image.ImageScanType) {
			return imageReason(repo, lastPr);
		}
		return switch (statusOf(repo)) {
			case ORPHANED -> "Its integration " + repo.getApiLabel()
					+ " was deleted. Delete the repository to clean up.";
			case GONE -> "Not found in the SCM at the last sync. A new pull request or sync"
					+ " brings it back.";
			case PAUSED -> "Scanning is paused: pull requests are not scanned and plans skip it.";
			case INACTIVE -> "No pull request for " + ago(lastPr) + " (more than "
					+ inactiveDays + " days).";
			case ACTIVE -> lastPr > 0 ? "Last pull request scanned " + ago(lastPr) + " ago."
					: "No pull requests yet. Repository scans still cover it.";
		};
	}

	/** The same states in image terms: images are pushed and scanned, there are no pull requests. */
	private String imageReason(RepositoryEntity repo, long lastScan) {
		return switch (statusOf(repo)) {
			case ORPHANED -> "Its integration " + repo.getApiLabel()
					+ " was deleted. Delete the repository to clean up.";
			case GONE -> "Not found in the registry at the last sync. A new image push or sync brings it back.";
			case PAUSED -> "Scanning is paused: new images are not scanned.";
			case INACTIVE -> "No image scan for " + ago(lastScan) + " (more than " + inactiveDays + " days).";
			case ACTIVE -> lastScan > 0 ? "Last image scanned " + ago(lastScan) + " ago." : "No image scans yet.";
		};
	}

	/**
	 * @param epochMillis a past time, 0 for never
	 * @return how long ago, e.g. {@code 3 d}, {@code 5 h}, {@code 2 min}; {@code never} for 0
	 */
	public String ago(long epochMillis) {
		if (epochMillis <= 0) {
			return "never";
		}
		long minutes = Math.max(0, clock.millis() - epochMillis) / 60_000L;
		if (minutes < 60) {
			return minutes + " min";
		}
		if (minutes < 60 * 24) {
			return minutes / 60 + " h";
		}
		long days = minutes / (60 * 24);
		return days < 365 ? days + " d" : days / 365 + " y";
	}

	/**
	 * @param type     the scan type
	 * @param apiLabel the integration (tab), or null for every integration of the type
	 * @param filter   the inventory filter
	 * @return the query for the matching repositories
	 */
	public Specification<RepositoryEntity> matching(ScanType type, String apiLabel,
			RepositoryFilter filter) {
		Set<String> live = integrationLabels();
		long inactiveBefore = inactiveBefore();
		long coveredSince = coveredSince();
		return (root, query, cb) -> {
			List<Predicate> where = new ArrayList<>();
			where.add(cb.equal(root.get("scanType"), type));
			if (apiLabel != null) {
				where.add(cb.equal(root.get("apiLabel"), apiLabel));
			}
			if (!filter.text().isEmpty()) {
				where.add(cb.like(cb.lower(root.get("repoName")),
						"%" + escapeLike(filter.text().toLowerCase(Locale.ROOT)) + "%",
						LIKE_ESCAPE));
			}
			if (filter.label() != null) {
				where.add(cb.like(root.get("labels"),
						"%," + escapeLike(filter.label()) + ",%", LIKE_ESCAPE));
			}
			if (filter.team() != null) {
				where.add(cb.equal(cb.lower(root.get("team")),
						filter.team().toLowerCase(Locale.ROOT)));
			}
			if (filter.project() != null) {
				where.add(cb.equal(cb.lower(root.get("projectKey")),
						filter.project().toLowerCase(Locale.ROOT)));
			}
			if (filter.status() != null) {
				where.add(status(root, cb, filter.status(), live, inactiveBefore));
			}
			if (filter.coverage() != null) {
				where.add(coverage(root, query, cb, filter.coverage(), coveredSince));
			}
			return cb.and(where.toArray(Predicate[]::new));
		};
	}

	/**
	 * @param type     the scan type
	 * @param coverage how lately a repository scan covered it, or null for any
	 * @return the repositories that still exist in a live integration of that type (any pause),
	 *         optionally narrowed by coverage: what the dashboard's coverage boxes count. Only
	 *         that type's integrations count, so a registry (ECR) never adds to code repositories
	 */
	public Specification<RepositoryEntity> inScm(ScanType type, RepoCoverage coverage) {
		Set<String> live = integrationLabels(type);
		long coveredSince = coveredSince();
		return (root, query, cb) -> {
			if (live.isEmpty()) {
				return cb.disjunction();
			}
			Predicate base = cb.and(cb.equal(root.get("scanType"), type),
					cb.isTrue(root.get("enabled")), root.get("apiLabel").in(live));
			return coverage == null ? base
					: cb.and(base, coverage(root, query, cb, coverage, coveredSince));
		};
	}

	/** @return epoch millis after which a finished repository scan counts as recent */
	public long coveredSince() {
		return clock.millis() - RepoCoverage.WINDOW_DAYS * DAY_MILLIS;
	}

	private static Predicate coverage(Root<RepositoryEntity> root, CriteriaQuery<?> query,
			CriteriaBuilder cb, RepoCoverage coverage, long coveredSince) {
		if (coverage == RepoCoverage.NEVER) {
			return cb.isNull(root.get("lastRepoScanId"));
		}
		// The latest finished scan is one indexed row per repository (its primary key)
		Subquery<Long> recent = query.subquery(Long.class);
		Root<RepoScanEntity> scan = recent.from(RepoScanEntity.class);
		recent.select(scan.get("id")).where(cb.equal(scan.get("id"),
				root.get("lastRepoScanId")), cb.greaterThanOrEqualTo(scan.get("endDate"),
						coveredSince));
		return coverage == RepoCoverage.RECENT ? cb.exists(recent)
				: cb.and(cb.isNotNull(root.get("lastRepoScanId")), cb.not(cb.exists(recent)));
	}

	private static Predicate status(Root<RepositoryEntity> root, CriteriaBuilder cb,
			RepoStatus status, Set<String> live, long inactiveBefore) {
		Predicate orphaned = live.isEmpty() ? cb.conjunction()
				: cb.not(root.get("apiLabel").in(live));
		if (status == RepoStatus.ORPHANED) {
			return orphaned;
		}
		Predicate notOrphaned = live.isEmpty() ? cb.disjunction()
				: root.get("apiLabel").in(live);
		Predicate enabled = cb.isTrue(root.get("enabled"));
		Predicate paused = cb.isTrue(root.get("scanningPaused"));
		Predicate inactive = cb.and(cb.greaterThan(root.get("lastReviewedDate"), 0L),
				cb.lessThan(root.get("lastReviewedDate"), inactiveBefore));
		return switch (status) {
			case GONE -> cb.and(notOrphaned, cb.isFalse(root.get("enabled")));
			case PAUSED -> cb.and(notOrphaned, enabled, paused);
			case INACTIVE -> cb.and(notOrphaned, enabled, cb.isFalse(root.get("scanningPaused")),
					inactive);
			default -> cb.and(notOrphaned, enabled, cb.isFalse(root.get("scanningPaused")),
					cb.not(inactive));
		};
	}

	static String escapeLike(String value) {
		return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
	}
}
