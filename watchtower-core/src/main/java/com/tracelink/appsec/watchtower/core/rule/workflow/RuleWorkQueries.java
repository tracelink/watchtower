package com.tracelink.appsec.watchtower.core.rule.workflow;

import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;
import com.tracelink.appsec.watchtower.core.persistence.FindingFeedbackEntity;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.persistence.RuleCandidateEntity;
import com.tracelink.appsec.watchtower.core.persistence.RuleMetricScanEntity;
import com.tracelink.appsec.watchtower.core.persistence.RuleReviewItemEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleState;
import com.tracelink.appsec.watchtower.core.rule.RuleStewardship;

import jakarta.persistence.Tuple;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Order;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Selection;
import jakarta.persistence.criteria.Subquery;

/**
 * The Rule work queries, built with the JPA Criteria API. Nothing here assembles query text: every value
 * (search, owner, window, thresholds) is a typed parameter of a query object, so no request input can become
 * part of a query. The rules each queue lists are the same ones the earlier JPQL text listed
 * ({@code RuleWorkQueuesTest} pins them).
 */
final class RuleWorkQueries {
	private static final List<String> REVIEWED = List.of("TRUE_POSITIVE", "FALSE_POSITIVE");
	private static final List<String> OPEN_REVIEW = List.of("OPEN", "IN_REVIEW");
	private static final List<String> CANDIDATE_STATES = List.of("DRAFT", "SHADOW");
	/** The character that escapes % and _ in the LIKE patterns {@link RuleReviewWorkspace#pattern} builds. */
	private static final char ESCAPE = '!';

	/** One page of rows, and how many rows there are in all. */
	record Rows(List<Map<String, Object>> rows, long total) {
	}

	private final LedgerRepository records;
	private final RuleHealthService health;
	private final RuleService rules;

	RuleWorkQueries(LedgerRepository records, RuleHealthService health, RuleService rules) {
		this.records = records;
		this.health = health;
		this.rules = rules;
	}

	Rows page(String queue, RuleWorkService.Filter filter, int offset, int limit) {
		CriteriaBuilder cb = records.criteria();
		CriteriaQuery<Tuple> query = cb.createTupleQuery();
		Scope scope = new Scope(cb, query, queue, filter);
		query.multiselect(scope.columns()).where(scope.where()).orderBy(scope.order());
		return new Rows(records.maps(query, offset, limit), count(queue, filter));
	}

	long count(String queue, RuleWorkService.Filter filter) {
		CriteriaBuilder cb = records.criteria();
		CriteriaQuery<Long> query = cb.createQuery(Long.class);
		Scope scope = new Scope(cb, query, queue, filter);
		query.select(cb.count("candidates".equals(queue) ? scope.candidate : scope.rule)).where(scope.where());
		return records.scalar(query);
	}

	/** Findings recorded per rule and revision inside the window, for the rules on the page. */
	List<Map<String, Object>> matchesFor(List<Long> ruleIds, long since) {
		CriteriaBuilder cb = records.criteria();
		CriteriaQuery<Tuple> query = cb.createTupleQuery();
		Root<RuleMetricScanEntity> metric = query.from(RuleMetricScanEntity.class);
		query.multiselect(metric.get("ruleId").alias("rule_id"), metric.get("revision").alias("revision"),
				cb.sum(metric.<Long>get("findings")).alias("n"))
				.where(metric.get("ruleId").in(ruleIds), cb.greaterThanOrEqualTo(metric.<Long>get("bucketStart"), since))
				.groupBy(metric.get("ruleId"), metric.get("revision"));
		return records.maps(query, 0, ruleIds.size() * 50);
	}

	/** Human judgments per rule, revision and judgment inside the window, for the rules on the page. */
	List<Map<String, Object>> judgmentsFor(List<Long> ruleIds, long since) {
		CriteriaBuilder cb = records.criteria();
		CriteriaQuery<Tuple> query = cb.createTupleQuery();
		Root<FindingFeedbackEntity> feedback = query.from(FindingFeedbackEntity.class);
		query.multiselect(feedback.get("ruleId").alias("rule_id"), feedback.get("revision").alias("revision"),
				feedback.get("judgment").alias("judgment"), cb.count(feedback).alias("n"))
				.where(feedback.get("ruleId").in(ruleIds), cb.greaterThanOrEqualTo(feedback.<Long>get("occurredAt"), since),
						projected(cb, query, feedback))
				.groupBy(feedback.get("ruleId"), feedback.get("revision"), feedback.get("judgment"));
		return records.maps(query, 0, ruleIds.size() * 150);
	}

	/** The same matched-projection condition the health page applies to its reviewed sample. */
	private static Predicate projected(CriteriaBuilder cb, jakarta.persistence.criteria.AbstractQuery<?> query,
			Root<FindingFeedbackEntity> feedback) {
		Subquery<Long> scan = query.subquery(Long.class);
		Root<RuleMetricScanEntity> metric = scan.from(RuleMetricScanEntity.class);
		scan.select(metric.<Long>get("scanId")).where(cb.equal(metric.get("scanType"), feedback.get("scanType")),
				cb.equal(metric.get("scanId"), feedback.get("scanId")), cb.equal(metric.get("ruleId"), feedback.get("ruleId")),
				cb.equal(metric.get("revision"), feedback.get("revision")));
		return cb.exists(scan);
	}

	/** One queue's roots, predicates, columns and order, for one filter. */
	private final class Scope {
		final CriteriaBuilder cb;
		final CriteriaQuery<?> query;
		final String queue;
		final RuleWorkService.Filter filter;
		final long since;
		final Root<RuleEntity> rule;
		/** Only the candidates queue lists candidates; the others leave this null. */
		final Root<RuleCandidateEntity> candidate;

		Scope(CriteriaBuilder cb, CriteriaQuery<?> query, String queue, RuleWorkService.Filter filter) {
			this.cb = cb;
			this.query = query;
			this.queue = queue;
			this.filter = filter;
			this.since = RuleWorkService.since(filter.days());
			this.candidate = "candidates".equals(queue) ? query.from(RuleCandidateEntity.class) : null;
			this.rule = query.from(RuleEntity.class);
		}

		<T> Path<T> stewardship(String attribute) {
			return rule.get("stewardship").get(attribute);
		}

		/** The rule's plain values; the type names the module without loading the entity. */
		List<Selection<?>> columns() {
			List<Selection<?>> columns = new ArrayList<>();
			if (candidate != null) {
				columns.add(candidate.alias("candidate"));
			}
			columns.add(rule.get("id").alias("rule_id"));
			columns.add(rule.get("name").alias("rule_name"));
			columns.add(rule.type().alias("rule_type"));
			columns.add(stewardship("owner").alias("owner"));
			columns.add(stewardship("reviewBy").alias("review_by"));
			columns.add(stewardship("cwe").alias("cwe"));
			columns.add(stewardship("revision").alias("revision"));
			columns.add(stewardship("securityRelevance").alias("security_relevance"));
			return columns;
		}

		Predicate where() {
			List<Predicate> all = new ArrayList<>();
			all.add(cb.equal(stewardship("state"), RuleState.ACTIVE));
			all.add(cb.like(cb.lower(rule.<String>get("name")), RuleReviewWorkspace.pattern(filter.search()), ESCAPE));
			switch (queue) {
				case "review" -> {
					all.add(ruleOwner());
					all.add(cb.or(cb.and(cb.greaterThan(matches(), 0L), cb.lessThan(judged(REVIEWED), (long) health.minimumSample())),
							cb.greaterThan(judged(List.of("UNKNOWN")), 0L)));
				}
				case "investigate" -> {
					all.add(ruleOwner());
					Expression<Double> reviewed = cb.toDouble(judged(REVIEWED));
					Expression<Double> falsePositives = cb.toDouble(judged(List.of("FALSE_POSITIVE")));
					all.add(cb.greaterThanOrEqualTo(judged(REVIEWED), (long) health.minimumSample()));
					all.add(cb.greaterThanOrEqualTo(judged(List.of("FALSE_POSITIVE")), (long) health.minimumFalsePositives()));
					all.add(cb.greaterThanOrEqualTo(falsePositives, cb.prod(health.falsePositiveRate(), reviewed)));
				}
				case "reviews" -> {
					// Open reviews count for every revision: a pending review is work whichever revision it names.
					all.add(cb.or(ruleOwner(), pendingReview(true)));
					all.add(cb.or(cb.lessThan(stewardship("reviewBy").as(LocalDate.class), LocalDate.now(ZoneOffset.UTC)),
							pendingReview(false)));
				}
				case "candidates" -> {
					all.add(ruleOwner());
					all.add(cb.equal(candidate.get("ruleId"), rule.get("id")));
					all.add(candidate.get("status").in(CANDIDATE_STATES));
				}
				default -> {
					all.add(ruleOwner());
					all.add(scanner());
					all.add(cb.or(setupGaps().toArray(Predicate[]::new)));
				}
			}
			return cb.and(all.toArray(Predicate[]::new));
		}

		List<Order> order() {
			return switch (queue) {
				case "review" -> List.of(cb.desc(matches()), cb.asc(rule.get("name")), cb.asc(rule.get("id")));
				case "investigate" -> List.of(cb.desc(judged(List.of("FALSE_POSITIVE"))), cb.asc(rule.get("name")),
						cb.asc(rule.get("id")));
				case "reviews" -> List.of(
						cb.asc(cb.<Integer>selectCase().when(cb.isNull(stewardship("reviewBy")), 1).otherwise(0)),
						cb.asc(stewardship("reviewBy")), cb.asc(rule.get("name")), cb.asc(rule.get("id")));
				case "candidates" -> List.of(cb.desc(candidate.get("updatedAt")), cb.asc(candidate.get("candidateId")));
				default -> List.of(cb.asc(rule.get("name")), cb.asc(rule.get("id")));
			};
		}

		/** The owner filter: "Assigned to me" is exact, the owner box is a contains match. */
		private String ownerPattern() {
			String pattern = RuleReviewWorkspace.pattern(filter.owner());
			return filter.exactOwner() ? pattern.substring(1, pattern.length() - 1) : pattern;
		}

		private Predicate ownerLike(Expression<String> owner) {
			return cb.like(cb.lower(cb.coalesce(owner, "")), ownerPattern(), ESCAPE);
		}

		private Predicate ruleOwner() {
			return ownerLike(stewardship("owner"));
		}

		/** A saved review is waiting on this rule; with {@code ownedBy} it must also be owned by the owner filter. */
		private Predicate pendingReview(boolean ownedBy) {
			Subquery<String> pending = query.subquery(String.class);
			Root<RuleReviewItemEntity> review = pending.from(RuleReviewItemEntity.class);
			List<Predicate> conditions = new ArrayList<>(List.of(cb.equal(review.get("ruleId"), rule.get("id")),
					review.get("status").in(OPEN_REVIEW)));
			if (ownedBy) {
				conditions.add(ownerLike(review.get("owner")));
			}
			pending.select(review.<String>get("reviewId")).where(conditions.toArray(Predicate[]::new));
			return cb.exists(pending);
		}

		/**
		 * Setup gaps can be taken one scanner at a time. Each module stores its rules as its own rule subclass,
		 * so the filter is the subclass, not a list of ids that a new rule could miss.
		 */
		private Predicate scanner() {
			if (filter.allScanners()) {
				return cb.conjunction();
			}
			List<Class<? extends RuleEntity>> types = rules.ruleTypesOfModule(filter.scanner());
			return types.isEmpty() ? cb.disjunction() : rule.type().in(types);
		}

		private List<Predicate> setupGaps() {
			List<Predicate> gaps = new ArrayList<>();
			if (List.of("all", "owner").contains(filter.gap())) {
				gaps.add(blank(stewardship("owner")));
			}
			if (List.of("all", "cwe").contains(filter.gap())) {
				// A style or quality rule marked "not a security rule" has no CWE by design.
				Path<String> relevance = stewardship("securityRelevance");
				gaps.add(cb.and(blank(stewardship("cwe")),
						cb.or(cb.isNull(relevance), cb.notEqual(relevance, RuleStewardship.NOT_SECURITY))));
			}
			if (filter.canSeeScans() && List.of("all", "nomatches").contains(filter.gap())) {
				gaps.add(cb.and(cb.equal(matches(), 0L), engineRanOnCurrentRevision()));
			}
			if (gaps.isEmpty()) {
				// A viewer without scan access asked only for the scan-based gap: nothing to show them.
				gaps.add(cb.disjunction());
			}
			return gaps;
		}

		private Predicate blank(Expression<String> text) {
			return cb.or(cb.isNull(text), cb.equal(cb.trim(text), ""));
		}

		private Predicate engineRanOnCurrentRevision() {
			Subquery<Long> ran = query.subquery(Long.class);
			Root<RuleMetricScanEntity> metric = ran.from(RuleMetricScanEntity.class);
			ran.select(metric.<Long>get("scanId")).where(cb.equal(metric.get("ruleId"), rule.get("id")),
					cb.equal(metric.get("revision"), stewardship("revision")),
					cb.greaterThanOrEqualTo(metric.<Long>get("bucketStart"), since),
					cb.equal(metric.get("engineStatus"), "RAN"));
			return cb.exists(ran);
		}

		/** Matches recorded for the rule's current revision inside the window (same units as health). */
		private Expression<Long> matches() {
			Subquery<Long> total = query.subquery(Long.class);
			Root<RuleMetricScanEntity> metric = total.from(RuleMetricScanEntity.class);
			total.select(cb.coalesce(cb.sum(metric.<Long>get("findings")), 0L)).where(
					cb.equal(metric.get("ruleId"), rule.get("id")), cb.equal(metric.get("revision"), stewardship("revision")),
					cb.greaterThanOrEqualTo(metric.<Long>get("bucketStart"), since));
			return total;
		}

		/** Human judgments on projected occurrences, counted the way the health page counts its sample. */
		private Expression<Long> judged(List<String> judgments) {
			Subquery<Long> count = query.subquery(Long.class);
			Root<FindingFeedbackEntity> feedback = count.from(FindingFeedbackEntity.class);
			count.select(cb.count(feedback)).where(cb.equal(feedback.get("ruleId"), rule.get("id")),
					cb.equal(feedback.get("revision"), stewardship("revision")),
					cb.greaterThanOrEqualTo(feedback.<Long>get("occurredAt"), since), feedback.get("judgment").in(judgments),
					projected(cb, count, feedback));
			return count;
		}
	}
}
