package com.tracelink.appsec.watchtower.core.rule;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.tracelink.appsec.watchtower.core.persistence.LedgerRepository;

/**
 * Stores the current definition revision on rules that predate V060, whose stored revision was
 * left NULL. Scans record the computed revision, so without it the rule work overview could not
 * match a legacy rule to its own metrics and feedback. Only the stored copy of the current
 * definition is filled: historical finding revisions are never touched. The update is
 * conditional (still NULL) so pods racing at startup cannot overwrite a fresh value, and it is a
 * bulk JPQL update so the rule's "updated" time does not change.
 */
@Component
public class RuleRevisionBackfill {
	private static final Logger LOG = LoggerFactory.getLogger(RuleRevisionBackfill.class);
	private static final int BATCH = 200;

	private final LedgerRepository records;
	private final TransactionTemplate transactions;

	public RuleRevisionBackfill(LedgerRepository records, PlatformTransactionManager transactionManager) {
		this.records = records;
		this.transactions = new TransactionTemplate(transactionManager);
	}

	@EventListener(ApplicationReadyEvent.class)
	public void onReady() {
		try {
			int filled = backfill();
			if (filled > 0) {
				LOG.info("Stored the current revision on {} rules that predate rule stewardship", filled);
			}
		} catch (RuntimeException e) {
			// Never block startup: the rule work overview only under-reports these rules until next boot.
			LOG.warn("Could not store current rule revisions; legacy rules may be missing from Rule work", e);
		}
	}

	/** Returns how many rules received a stored revision. */
	public int backfill() {
		int filled = 0;
		long after = 0;
		while (true) {
			long cursor = after;
			Map<Long, String> batch = transactions.execute(status -> revisions(cursor));
			if (batch == null || batch.isEmpty()) {
				return filled;
			}
			for (var rule : batch.entrySet()) {
				after = Math.max(after, rule.getKey());
				if (rule.getValue() != null) {
					filled += records.update("UPDATE RuleEntity r SET r.stewardship.revision=?1"
							+ " WHERE r.id=?2 AND r.stewardship.revision IS NULL", rule.getValue(), rule.getKey());
				}
			}
		}
	}

	/** Computes revisions while the session is open, before any update clears it. */
	private Map<Long, String> revisions(long after) {
		List<RuleEntity> rules = records.list(RuleEntity.class, "SELECT r FROM RuleEntity r"
				+ " WHERE r.stewardship.revision IS NULL AND r.id>?1 ORDER BY r.id", 0, BATCH, after);
		Map<Long, String> revisions = new LinkedHashMap<>();
		rules.forEach(rule -> revisions.put(rule.getId(), rule.toDto().getRevision()));
		return revisions;
	}
}
