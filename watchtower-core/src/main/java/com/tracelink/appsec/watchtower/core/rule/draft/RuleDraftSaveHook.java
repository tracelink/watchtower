package com.tracelink.appsec.watchtower.core.rule.draft;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.rule.RuleState;
import com.tracelink.appsec.watchtower.core.rule.RuleStewardship;
import com.tracelink.appsec.watchtower.core.rule.RuleStewardshipUpdate;

/**
 * What happens after a person saves a rule that was opened from a draft: the new rule is owned by that person
 * and gets the draft's CWE, and the draft is closed so it is not offered again. The designers save the rule
 * themselves; this only follows, and it never turns a saved rule into an error.
 */
@Component
public class RuleDraftSaveHook {
	private static final Logger LOG = LoggerFactory.getLogger(RuleDraftSaveHook.class);
	/** The Regex designer renames rules saved as manual code review rules. */
	private static final String MCR_PREFIX = "MCR Match: ";

	private final RuleDraftService drafts;
	private final RuleService rules;

	public RuleDraftSaveHook(RuleDraftService drafts, RuleService rules) {
		this.drafts = drafts;
		this.rules = rules;
	}

	/**
	 * @param engine        the designer the rule was saved in
	 * @param draftId       the draft the page was opened from
	 * @param owner         the person who saved it
	 * @param submittedName the name typed in the save dialog
	 * @return the saved rule's name when the draft was applied to it
	 */
	public Optional<String> afterSave(String engine, String draftId, String owner, String submittedName) {
		try {
			Optional<RuleDraftData> draft = drafts.ownedOpen(draftId, owner).filter(found -> found.engine().equalsIgnoreCase(engine));
			if (draft.isEmpty() || submittedName == null) {
				return Optional.empty();
			}
			// The rule list is cached; the designer has just added to it.
			rules.invalidateRuleCache();
			Optional<RuleEntity> saved = List.of(submittedName.strip(), MCR_PREFIX + submittedName.strip()).stream()
					.map(rules::getRule).filter(found -> found != null && found.toDto().getModule().equalsIgnoreCase(engine)).findFirst();
			if (saved.isEmpty()) {
				return Optional.empty();
			}
			RuleEntity rule = saved.get();
			RuleStewardship current = rule.getStewardship();
			String cwe = draft.get().cwe() != null ? draft.get().cwe() : current.getCwe();
			String secondary = draft.get().cwe() != null ? draft.get().secondaryCwes() : current.getSecondaryCwes();
			rules.updateStewardship(rule.getId(), engine,
					new RuleStewardshipUpdate(current.getState() == null ? RuleState.ACTIVE : current.getState(), owner, current.getReviewBy(),
							cwe, secondary, false, current.getCategory()),
					owner);
			drafts.markUsed(draftId, owner, rule.getName());
			return Optional.of(rule.getName());
		} catch (Exception e) {
			// The rule is saved either way; the owner and CWE can be set on its page.
			LOG.warn("Could not apply a draft to the rule saved in the {} designer: {}", engine, e.getMessage());
			return Optional.empty();
		}
	}
}
