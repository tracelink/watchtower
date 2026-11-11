package com.tracelink.appsec.watchtower.core.cwe;

import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;
import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;
import com.tracelink.appsec.watchtower.core.persistence.RuleHealthEntity;

import jakarta.persistence.Tuple;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;

/**
 * Reads the stored rule health for coverage: did the rule's engine run successfully in the last 30 days,
 * and is the rule flagged as noisy over 90 days. Only health of the rule's current definition counts, and
 * rows older than two days are stale (as in the weekly report) and ignored.
 */
@Component
public class CweRuleHealthReader {
	/** What the stored health says about one rule. */
	public record Health(boolean ran, boolean noisy) {
	}

	private static final int ID_CHUNK = 500;
	private static final long STALE_MILLIS = 2L * 24 * 60 * 60 * 1000;
	private static final String UNKNOWN_REVISION = "unknown";
	private static final ObjectMapper MAPPER = new ObjectMapper();

	private final LedgerRepository records;
	private final Clock clock;

	@Autowired
	public CweRuleHealthReader(LedgerRepository records) {
		this(records, Clock.systemUTC());
	}

	CweRuleHealthReader(LedgerRepository records, Clock clock) {
		this.records = records;
		this.clock = clock;
	}

	/**
	 * @param revisionByRule each rule id with its current definition revision (null when it has none)
	 * @return health for the rules that have fresh evidence of their current definition
	 */
	public Map<Long, Health> read(Map<Long, String> revisionByRule) {
		Map<Long, Health> found = new HashMap<>();
		long freshAfter = clock.millis() - STALE_MILLIS;
		List<Long> ids = new ArrayList<>(revisionByRule.keySet());
		for (int from = 0; from < ids.size(); from += ID_CHUNK) {
			List<Long> chunk = ids.subList(from, Math.min(ids.size(), from + ID_CHUNK));
			for (Map<String, Object> row : records.maps(query(chunk), 0, Integer.MAX_VALUE)) {
				long ruleId = ((Number) row.get("rule_id")).longValue();
				String wanted = revisionByRule.get(ruleId) == null ? UNKNOWN_REVISION : revisionByRule.get(ruleId);
				if (!wanted.equals(row.get("revision_key")) || ((Number) row.get("computed_at")).longValue() < freshAfter) {
					continue;
				}
				parse((String) row.get("evidence_json")).ifPresent(health -> found.put(ruleId, health));
			}
		}
		return Map.copyOf(found);
	}

	private CriteriaQuery<Tuple> query(List<Long> ruleIds) {
		CriteriaBuilder cb = records.criteria();
		CriteriaQuery<Tuple> query = cb.createTupleQuery();
		Root<RuleHealthEntity> health = query.from(RuleHealthEntity.class);
		query.multiselect(health.get("ruleId").alias("rule_id"), health.get("revisionKey").alias("revision_key"),
				health.get("computedAt").alias("computed_at"), health.get("evidenceJson").alias("evidence_json"));
		query.where(health.get("ruleId").in(ruleIds));
		return query;
	}

	private static java.util.Optional<Health> parse(String evidenceJson) {
		try {
			JsonNode evidence = MAPPER.readTree(evidenceJson);
			boolean ran = evidence.path("30d").path("successful_engine_scans").asLong(0) > 0;
			boolean noisy = false;
			for (JsonNode chip : evidence.path("90d").path("chips")) {
				noisy |= RuleHealthService.NEEDS_REVIEW.equals(chip.asText());
			}
			return java.util.Optional.of(new Health(ran, noisy));
		} catch (Exception e) {
			return java.util.Optional.empty();
		}
	}
}
