package com.tracelink.appsec.module.betterleaks.allowlist;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleDto;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingAction;
import com.tracelink.appsec.watchtower.core.scan.presentation.FindingContext;
import com.tracelink.appsec.watchtower.core.scan.presentation.IFindingActionProvider;

/**
 * "Allowlist…" on a Betterleaks finding of a PR report (§4.15): opens the allowlist page with an
 * entry for this repository, file and rule pre-filled. The user still gives the reason and saves,
 * so the allowlist's own validation and audit apply.
 *
 * @author Watchtower
 */
@Component
public class BetterleaksAllowlistActionProvider implements IFindingActionProvider {

	static final String LABEL = "Allowlist…";

	@Override
	public Optional<FindingAction> actionFor(FindingContext finding,
			Authentication authentication) {
		if (!StringUtils.startsWith(finding.ruleName(), BetterleaksRuleDto.NAME_PREFIX)
				|| !hasAllowlistPrivilege(authentication)) {
			return Optional.empty();
		}
		String ruleId = StringUtils.removeStart(finding.ruleName(), BetterleaksRuleDto.NAME_PREFIX);
		return Optional.of(new FindingAction(LABEL, "/betterleaks/allowlist?repo="
				+ encode(finding.repoName()) + "&path=" + encode(finding.filePath()) + "&rule="
				+ encode(ruleId)));
	}

	private static boolean hasAllowlistPrivilege(Authentication authentication) {
		return authentication != null && authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.anyMatch(BetterleaksModule.ALLOWLIST_PRIVILEGE_NAME::equals);
	}

	private static String encode(String value) {
		return URLEncoder.encode(StringUtils.defaultString(value), StandardCharsets.UTF_8);
	}
}
