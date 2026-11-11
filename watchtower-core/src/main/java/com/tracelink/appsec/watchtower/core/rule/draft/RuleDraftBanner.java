package com.tracelink.appsec.watchtower.core.rule.draft;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;

/**
 * What the designer page shows above a drafted rule: that it came from the assistant and is not saved, the CWE
 * it will get, the examples it was drafted with, and where to discard it. Ready-made strings, so the template
 * has nothing to work out.
 *
 * @param id         the draft's id, for the save form
 * @param tip        the hover text of the "AI draft" chip
 * @param cwe        the CWE the saved rule will get, or null
 * @param cweTip     the hover text of the CWE chip
 * @param vulnerable the example the rule should flag, or null
 * @param safe       the example the rule should leave alone, or null
 * @param discardUrl where the discard button posts
 */
public record RuleDraftBanner(String id, String tip, String cwe, String cweTip, String vulnerable, String safe,
		String discardUrl) {

	public static RuleDraftBanner of(RuleDraftData draft) {
		String codeWarning = "eslint".equals(draft.engine())
				? "The rule is JavaScript that runs when you press Run rule, so read the create function first." : null;
		String tip = Stream.of("Drafted by the assistant for you to review.", draft.sourceLabel(),
				"Nothing is saved until you save the rule.", codeWarning, draft.rationale()).filter(part -> part != null && !part.isBlank())
				.map(part -> part.endsWith(".") ? part : part + ".").collect(Collectors.joining(" "));
		String all = draft.secondaryCwes() == null ? draft.cwe() : draft.cwe() + "," + draft.secondaryCwes();
		return new RuleDraftBanner(draft.id(), tip, all == null ? null : all.replace(",", ", "),
				"The rule gets this CWE when you save it. You can change it later on the rule page.", draft.vulnerableSnippet(),
				draft.safeSnippet(), "/designer/draft/" + draft.id() + "/discard");
	}
}
