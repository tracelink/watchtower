package com.tracelink.appsec.watchtower.core.rule.workflow;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.metrics.RuleHealthService;
import com.tracelink.appsec.watchtower.core.rule.report.RuleReportPresentation;
import com.tracelink.appsec.watchtower.core.rule.workflow.RuleWorkService.Chip;

class RuleDetailPresentationTest {

	private static Map<String, Object> health(String state, List<String> chips) {
		Map<String, Object> health = new HashMap<>();
		health.put("evidence_state", state);
		health.put("evidence_note", "note for " + state);
		health.put("chips", chips);
		health.put("findings", 1L);
		health.put("reviewed_sample", 1L);
		health.put("reviewed_fp_rate", 0.0);
		health.put("review_coverage", 1.0);
		health.put("tp", 1L);
		health.put("fp", 0L);
		health.put("unknown", 0L);
		health.put("selected_scans", 1L);
		health.put("successful_engine_scans", 0L);
		health.put("unknown_scans", 1L);
		return health;
	}

	@Test
	void insufficientDataReadsAsPlainWordsWithTheNeededSample() {
		var view = RuleDetailPresentation.health(health("MATCHES", List.of(RuleHealthService.INSUFFICIENT_DATA)), 6);

		Chip chip = view.headerChips().getFirst();
		assertThat(chip.text()).isEqualTo("Too little data to judge");
		assertThat(chip.tone()).isEqualTo("warn");
		assertThat(chip.tip()).contains("1 of 6 needed");
	}

	@Test
	void compactChipsSayTooLittleDataWithTheCountStillNeeded() {
		var health = health("MATCHES", List.of(RuleHealthService.INSUFFICIENT_DATA, RuleHealthService.NO_RECENT_MATCHES));
		health.put("days", 90);

		var chips = RuleDetailPresentation.compactHealthChips(health, 6);

		assertThat(chips).extracting(Chip::text).containsExactly("Too little data", "No recent matches");
		assertThat(chips.getFirst().tone()).isEqualTo("warn");
		assertThat(chips.getFirst().tip()).isEqualTo("1 of 6 reviewed findings needed to judge this rule in 90 days.");
	}

	@Test
	void eachZeroMatchStateKeepsItsOwnChipAndExplanation() {
		var none = RuleDetailPresentation.health(health("NO_ELIGIBLE_EVIDENCE", List.of()), 6).evidenceChip();
		var ran = RuleDetailPresentation.health(health("SUCCESSFUL_ENGINE_ZERO_MATCHES", List.of()), 6).evidenceChip();
		var unverified = RuleDetailPresentation.health(health("UNVERIFIED_ZERO_MATCHES", List.of()), 6).evidenceChip();

		assertThat(List.of(none.text(), ran.text(), unverified.text())).doesNotHaveDuplicates();
		assertThat(none.tip()).isEqualTo("note for NO_ELIGIBLE_EVIDENCE");
		assertThat(ran.tone()).isEqualTo("ok");
		assertThat(unverified.tone()).isEqualTo("warn");
	}

	@Test
	void tilesJudgmentsAndRunChipsComeFromTheCalculatedNumbers() {
		var view = RuleDetailPresentation.health(health("MATCHES", List.of()), 6);

		assertThat(view.tiles()).extracting(RuleDetailPresentation.Tile::value)
				.containsExactly("1", "1", "0.0 %", "100.0 %");
		assertThat(view.judgments().truePercent()).isEqualTo(100);
		assertThat(view.judgments().unknownPercent()).isZero();
		assertThat(view.runChips()).extracting(Chip::text).contains("1 eligible scan", "0 confirmed runs", "1 unknown",
				"Checked places: unknown");
	}

	@Test
	void missingRatesShowADashNotZero() {
		var health = health("NO_ELIGIBLE_EVIDENCE", List.of());
		health.put("reviewed_fp_rate", null);
		health.put("review_coverage", null);

		var tiles = RuleDetailPresentation.health(health, 6).tiles();

		assertThat(tiles.get(2).value()).isEqualTo("—");
		assertThat(tiles.get(3).value()).isEqualTo("—");
	}

	@Test
	void codesBecomeWords() {
		assertThat(RuleDetailPresentation.reviewStatus("IN_REVIEW").label()).isEqualTo("In review");
		assertThat(RuleDetailPresentation.scanScope("pull_request").label()).isEqualTo("Pull requests");
		assertThat(RuleDetailPresentation.policy("nonblocking").label()).isEqualTo("Not blocking");
		assertThat(RuleReportPresentation.reason("CONFIRMED_NOISE").label()).isEqualTo("Confirmed noise");
		assertThat(RuleReportPresentation.periodLabel("2026-W42")).isEqualTo("Week 42");
		assertThat(RuleReportPresentation.periodLabel(null)).isEqualTo("Manual");
		assertThat(RuleReportPresentation.scheduleLabel(Map.of("enabled", true, "weekday", 3)))
				.isEqualTo("Weekly · Wednesday (UTC)");
		assertThat(RuleReportPresentation.scheduleLabel(Map.of("enabled", false, "weekday", 3))).isEqualTo("Schedule off");
	}

	@Test
	void scopeChipMarksAnOlderRevisionAndKeepsTheHashOnHover() {
		String current = "a".repeat(64);
		String older = "b".repeat(64);

		var chip = RuleDetailPresentation.scopeChip(older, current, 30, "upload", "all");

		assertThat(chip.text()).isEqualTo("Older revision · 30 d");
		assertThat(chip.tone()).isEqualTo("warn");
		assertThat(chip.tip()).contains(older).contains("uploads");
		assertThat(RuleDetailPresentation.scopeChip(current, current, 90, "all", "all").text())
				.isEqualTo("Current revision · 90 d");
	}
}
