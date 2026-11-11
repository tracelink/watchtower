package com.tracelink.appsec.watchtower.core.rule.knowledge;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.mvc.PagedResult;
import com.tracelink.appsec.watchtower.core.persistence.FindingFeedbackEntity;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.persistence.MissedVulnerabilityCaseEntity;
import com.tracelink.appsec.watchtower.core.persistence.RuleReviewItemEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleState;
import com.tracelink.appsec.watchtower.core.rule.workflow.RuleReviewWorkspace;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/**
 * The knowledge page's read model (UAT #23): entries with repository, rule and evidence names
 * instead of stored IDs, and searchable options for the proposal pickers. Writes stay in
 * {@link KnowledgeService}, which keeps the second-person approval rule.
 */
@Service
@Transactional(readOnly = true)
public class KnowledgeWorkspace {
	public static final List<String> STATUSES = List.of(KnowledgeService.APPROVED, KnowledgeService.PROPOSED,
			KnowledgeService.RETIRED, KnowledgeService.REJECTED);
	public static final Set<String> OPTION_KINDS = Set.of("repositories", "rules", "review", "finding_feedback",
			"missed_case");
	private static final Map<String, String> KIND_LABELS = Map.of("SANITIZER", "Sanitizer", "SOURCE", "Source",
			"SINK", "Sink", "FRAMEWORK_GUARANTEE", "Framework guarantee", "NOTE", "Note");
	private static final String SEARCH = " LIKE ?1 ESCAPE '!'";

	private final LedgerRepository records;

	public KnowledgeWorkspace(LedgerRepository records) {
		this.records = records;
	}

	/** A picker choice or a resolved reference: stored id, readable label and a short preview. */
	public record Option(String id, String label, String preview) {
	}

	public record Entry(String id, String kind, String statement, String language, String library,
			String versionRange, boolean allRepositories, List<Option> repositories, List<Option> rules,
			List<String> cwes, List<Option> evidence, String status, String reviewBy, boolean stale,
			String proposedBy, long proposedAt, String decidedBy, Long decidedAt, String decisionNote, long version,
			boolean ownProposal, boolean canApprove) {
	}

	public PagedResult<Entry> entries(String status, String search, int page, int size, String viewer,
			boolean canSeeScans) {
		requireStatus(status);
		RuleReviewWorkspace.bounds(page, size);
		String pattern = RuleReviewWorkspace.pattern(search);
		String from = "FROM KnowledgeEntity k WHERE k.status=?2 AND (LOWER(k.statement)" + SEARCH
				+ " OR LOWER(k.library)" + SEARCH + ")";
		List<KnowledgeEntity> rows = records.list(KnowledgeEntity.class,
				"SELECT k " + from + " ORDER BY k.proposedAt DESC,k.knowledgeId", page * size, size, pattern, status);
		long total = records.scalar(Long.class, "SELECT COUNT(k) " + from, pattern, status);
		var names = new Names(rows, canSeeScans);
		List<Entry> entries = rows.stream().map(row -> entry(row, names, viewer)).toList();
		return RuleReviewWorkspace.page(entries, page, size, total);
	}

	public Map<String, Long> counts(String search) {
		String pattern = RuleReviewWorkspace.pattern(search);
		Map<String, Long> counts = new LinkedHashMap<>();
		for (String status : STATUSES) {
			counts.put(status, records.scalar(Long.class, "SELECT COUNT(k) FROM KnowledgeEntity k WHERE k.status=?2"
					+ " AND (LOWER(k.statement)" + SEARCH + " OR LOWER(k.library)" + SEARCH + ")", pattern, status));
		}
		return counts;
	}

	/** Searchable choices for one picker. The controller decides who may see scan-derived judgments. */
	public PagedResult<Option> options(String kind, String search, List<Long> ruleIds, int page, int size) {
		if (!OPTION_KINDS.contains(kind)) {
			throw new IllegalArgumentException("Unknown option list");
		}
		RuleReviewWorkspace.bounds(page, size);
		String pattern = RuleReviewWorkspace.pattern(search);
		List<Long> rules = ruleIds == null ? List.of() : List.copyOf(ruleIds);
		String ruleScope = rules.isEmpty() ? "" : " AND %s.ruleId IN ?2";
		Object[] args = rules.isEmpty() ? new Object[] {pattern} : new Object[] {pattern, rules};
		return switch (kind) {
			case "repositories" -> page(RepositoryEntity.class, "r", "FROM RepositoryEntity r WHERE LOWER(r.repoName)"
					+ SEARCH + " OR LOWER(r.apiLabel)" + SEARCH, "r.repoName,r.id", KnowledgeWorkspace::repository,
					page, size, pattern);
			case "rules" -> page(RuleEntity.class, "r", "FROM RuleEntity r WHERE LOWER(r.name)" + SEARCH
					+ " AND r.stewardship.state=?2", "r.name,r.id", KnowledgeWorkspace::rule, page, size, pattern,
					RuleState.ACTIVE);
			case "review" -> page(RuleReviewItemEntity.class, "r", "FROM RuleReviewItemEntity r WHERE r.status='ACCEPTED'"
					+ " AND (LOWER(r.reason)" + SEARCH + " OR LOWER(COALESCE(r.outcome,''))" + SEARCH + ")"
					+ ruleScope.formatted("r"), "r.updatedAt DESC,r.reviewId", KnowledgeWorkspace::review, page, size, args);
			case "finding_feedback" -> page(FindingFeedbackEntity.class, "f", "FROM FindingFeedbackEntity f WHERE"
					+ " LOWER(COALESCE(f.explanation,''))" + SEARCH + ruleScope.formatted("f"),
					"f.updatedAt DESC,f.occurrenceKey", KnowledgeWorkspace::judgment, page, size, args);
			default -> page(MissedVulnerabilityCaseEntity.class, "c", "FROM MissedVulnerabilityCaseEntity c WHERE"
					+ " LOWER(c.repositoryName)" + SEARCH + " OR LOWER(c.affectedPath)" + SEARCH
					+ " OR LOWER(COALESCE(c.cwe,''))" + SEARCH, "c.createdAt DESC,c.caseId",
					KnowledgeWorkspace::missedCase, page, size, pattern);
		};
	}

	/** The rule named in a "propose from here" link, if it still exists. */
	public Option rule(long ruleId) {
		var rule = records.find(RuleEntity.class, ruleId);
		return rule == null ? null : rule(rule);
	}

	/** An accepted review named in a "propose from here" link; other states cannot be evidence. */
	public Option acceptedReview(String reviewId) {
		var review = records.find(RuleReviewItemEntity.class, reviewId);
		return review == null || !"ACCEPTED".equals(review.status) ? null : review(review);
	}

	public static String kindLabel(String kind) {
		return KIND_LABELS.getOrDefault(kind, kind);
	}

	public static void requireStatus(String status) {
		if (!STATUSES.contains(status)) {
			throw new IllegalArgumentException("Unknown knowledge status");
		}
	}

	// --- Mapping ---

	private Entry entry(KnowledgeEntity row, Names names, String viewer) {
		boolean stale = LocalDate.parse(row.getReviewBy()).isBefore(LocalDate.now(ZoneOffset.UTC));
		boolean own = row.getProposedBy().equalsIgnoreCase(viewer);
		boolean proposed = KnowledgeService.PROPOSED.equals(row.getStatus());
		List<Option> repositories = KnowledgeService.longs(row.getRepositoryIds()).stream()
				.map(id -> names.repositories.getOrDefault(id, new Option(String.valueOf(id), "Removed repository", null)))
				.toList();
		List<Option> rules = KnowledgeService.longs(row.getRuleIds()).stream()
				.map(id -> names.rules.getOrDefault(id, new Option(String.valueOf(id), "Deleted rule", null))).toList();
		List<Option> evidence = KnowledgeService.evidenceOf(row.getEvidenceJson()).stream()
				.map(names::evidence).toList();
		return new Entry(row.getKnowledgeId(), row.getKind(), row.getStatement(), row.getLanguage(), row.getLibrary(),
				row.getVersionRange(), row.isAllRepositories(), repositories, rules,
				KnowledgeService.strings(row.getCwes()), evidence, row.getStatus(), row.getReviewBy(), stale,
				row.getProposedBy(), row.getProposedAt(), row.getDecidedBy(), row.getDecidedAt(), row.getDecisionNote(),
				row.getVersion(), own, proposed && !own && !stale);
	}

	private static Option repository(RepositoryEntity repository) {
		return new Option(String.valueOf(repository.getId()), repository.getApiLabel() + " / " + repository.getRepoName(),
				null);
	}

	private static Option rule(RuleEntity rule) {
		return new Option(String.valueOf(rule.getId()), rule.getName() + " (" + rule.toDto().getModule() + ")", null);
	}

	private static Option review(RuleReviewItemEntity review) {
		return new Option(review.reviewId, "Accepted review: " + review.reason,
				orElse(review.outcome, review.recommendation));
	}

	private static Option judgment(FindingFeedbackEntity feedback) {
		String judgment = feedback.judgment.toLowerCase(Locale.ROOT).replace('_', ' ');
		return new Option(feedback.occurrenceKey, "Finding judgment: " + judgment + " in "
				+ feedback.scanType.replace('_', ' ') + " scan " + feedback.scanId,
				orElse(feedback.explanation, "") + " · reviewed by " + feedback.reviewer);
	}

	private static Option missedCase(MissedVulnerabilityCaseEntity missed) {
		return new Option(missed.caseId, "Missed vulnerability: " + missed.repositoryName + " " + missed.affectedPath
				+ (missed.firstLine == null ? "" : ":" + missed.firstLine),
				orElse(missed.cwe, "no CWE") + " · " + orElse(missed.language, "language unknown"));
	}

	private static String orElse(String value, String fallback) {
		return value == null || value.isBlank() ? fallback : value;
	}

	private <T> PagedResult<Option> page(Class<T> type, String alias, String from, String order,
			Function<T, Option> mapper, int page, int size, Object... args) {
		var rows = records.list(type, "SELECT " + alias + " " + from + " ORDER BY " + order, page * size, size, args);
		long total = records.scalar(Long.class, "SELECT COUNT(" + alias + ") " + from, args);
		return RuleReviewWorkspace.page(rows.stream().map(mapper).toList(), page, size, total);
	}

	/** Names for every reference on one page, loaded with one query per kind. */
	private final class Names {
		private final Map<Long, Option> repositories;
		private final Map<Long, Option> rules;
		private final Map<String, Option> reviews;
		private final Map<String, Option> judgments;
		private final Map<String, Option> missedCases;
		private final boolean canSeeScans;

		Names(List<KnowledgeEntity> rows, boolean canSeeScans) {
			this.canSeeScans = canSeeScans;
			var evidence = rows.stream().flatMap(row -> KnowledgeService.evidenceOf(row.getEvidenceJson()).stream()).toList();
			repositories = byLong(rows.stream().flatMap(row -> KnowledgeService.longs(row.getRepositoryIds()).stream())
					.collect(Collectors.toSet()), "SELECT r FROM RepositoryEntity r WHERE r.id IN ?1", RepositoryEntity.class,
					KnowledgeWorkspace::repository);
			rules = byLong(rows.stream().flatMap(row -> KnowledgeService.longs(row.getRuleIds()).stream())
					.collect(Collectors.toSet()), "SELECT r FROM RuleEntity r WHERE r.id IN ?1", RuleEntity.class,
					KnowledgeWorkspace::rule);
			reviews = byString(ids(evidence, "review"), "SELECT r FROM RuleReviewItemEntity r WHERE r.reviewId IN ?1",
					RuleReviewItemEntity.class, KnowledgeWorkspace::review);
			judgments = canSeeScans ? byString(ids(evidence, "finding_feedback"),
					"SELECT f FROM FindingFeedbackEntity f WHERE f.occurrenceKey IN ?1", FindingFeedbackEntity.class,
					KnowledgeWorkspace::judgment) : Map.of();
			missedCases = byString(ids(evidence, "missed_case"),
					"SELECT c FROM MissedVulnerabilityCaseEntity c WHERE c.caseId IN ?1", MissedVulnerabilityCaseEntity.class,
					KnowledgeWorkspace::missedCase);
		}

		Option evidence(KnowledgeService.Evidence reference) {
			Option found = switch (reference.type()) {
				case "review" -> reviews.get(reference.id());
				case "finding_feedback" -> canSeeScans ? judgments.get(reference.id())
						: new Option(reference.id(), "Finding judgment (requires Scan Results View)", null);
				default -> missedCases.get(reference.id());
			};
			return found != null ? found : new Option(reference.id(), "Evidence no longer available", null);
		}

		private static Set<String> ids(List<KnowledgeService.Evidence> evidence, String type) {
			return evidence.stream().filter(e -> type.equals(e.type())).map(KnowledgeService.Evidence::id)
					.collect(Collectors.toSet());
		}

		private <T> Map<Long, Option> byLong(Collection<Long> ids, String jpql, Class<T> type, Function<T, Option> mapper) {
			Map<Long, Option> result = new LinkedHashMap<>();
			if (!ids.isEmpty()) {
				records.list(type, jpql, 0, ids.size(), List.copyOf(ids)).stream().map(mapper)
						.forEach(option -> result.put(Long.valueOf(option.id()), option));
			}
			return result;
		}

		private <T> Map<String, Option> byString(Collection<String> ids, String jpql, Class<T> type,
				Function<T, Option> mapper) {
			Map<String, Option> result = new LinkedHashMap<>();
			if (!ids.isEmpty()) {
				records.list(type, jpql, 0, ids.size(), List.copyOf(ids)).stream().map(mapper)
						.forEach(option -> result.put(option.id(), option));
			}
			return result;
		}
	}
}
