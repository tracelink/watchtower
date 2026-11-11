package com.tracelink.appsec.module.regex.designer;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.regex.RegexModule;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.module.regex.scanner.RegexBenchmarking;
import com.tracelink.appsec.module.regex.scanner.RegexCallable;
import com.tracelink.appsec.watchtower.core.module.designer.DesignerMatch;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

/**
 * The Designer implementation for Regex
 *
 * @author csmith, mcool
 */
@Service
public class RegexRuleDesigner implements IRuleDesigner {
	private final String defaultSrc =
			"Watchtower Regex\n" + "Can help us find accessKeys\n" + "Or other data.";
	private final String defaultQuery = "accessKeys";

	/**
	 * Execute a query using the given query and code and return its result
	 * 
	 * @param query the Regex query
	 * @param code  the code to run against
	 * @return a {@linkplain RuleDesignerModelAndView} containing the model information describing
	 *         the result of this query
	 */
	public RuleDesignerModelAndView query(String query, String code) {
		RuleDesignerModelAndView mav = getBaseMAV();
		queryInternal(mav, query, code);
		return mav;
	}

	private RuleDesignerModelAndView getBaseMAV() {
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView("designer/regex");
		mav.addObject("rulePriorities", RulePriority.values());
		mav.addObject("help", getHelp());
		mav.addScriptReference("/scripts/regex-designer.js");
		return mav;
	}

	private void queryInternal(RuleDesignerModelAndView mav, String query, String source) {
		mav.addObject("query", query);
		mav.addObject("sourceCode", source);
		mav.addObject("matches", getMatches(query, source));
	}

	private List<DesignerMatch> getMatches(String query, String code) {
		if (StringUtils.isBlank(query)) {
			return List.of();
		}
		try {
			Pattern.compile(query);
		} catch (PatternSyntaxException e) {
			return List.of(DesignerMatch.note(
					"The regular expression does not compile: " + e.getDescription() + "."));
		}
		CodeScanReport report;
		try {
			report = getRegexReport(query, code);
		} catch (IOException e) {
			return List.of(DesignerMatch.note("Could not run the rule: the sample could not be written."));
		}
		if (!report.getErrors().isEmpty()) {
			return List.of(DesignerMatch.note(
					"The pattern did not finish on this sample, so it was stopped. It may take too long to match."));
		}
		return report.getViolations().stream()
				.map(sv -> DesignerMatch.atLine(sv.getLineNum(), "Matched by the pattern"))
				.collect(Collectors.toList());
	}


	private CodeScanReport getRegexReport(String query, String code) throws IOException {
		Path temp = Files.createTempFile(null, null);
		try (FileWriter fw = new FileWriter(temp.toFile())) {
			fw.write(code);
		}
		RegexCustomRuleDto rule = new RegexCustomRuleDto();
		rule.setName("Test Rule");
		rule.setPriority(RulePriority.LOW);
		rule.setRegexPattern(query);
		rule.setFileExtension("");
		RulesetDto ruleset = new RulesetDto();
		ruleset.setRules(Collections.singleton(rule));

		RegexCallable regex =
				new RegexCallable(temp, ruleset,
						new RegexBenchmarking());
		CodeScanReport report = regex.call();

		FileUtils.deleteQuietly(temp.toFile());
		return report;
	}

	private static Map<String, String> getHelp() {
		Map<String, String> help = new HashMap<String, String>();
		help.put("regexSource",
				"The Source Code Section is where Rule Designers should put all source code to be tested.");
		help.put("regex",
				"A regular expression. Each line of the sample it matches is a finding.");
		return help;
	}

	@Override
	public RuleDesignerModelAndView getDefaultRuleDesignerModelAndView() {
		return query(defaultQuery, defaultSrc);
	}

	/** The drafted pattern, already run on the drafted example, with the save dialog's fields filled in. */
	@Override
	public RuleDesignerModelAndView getPrefilledRuleDesignerModelAndView(RuleDraftData draft) {
		RuleDesignerModelAndView mav = query(draft.definition(), StringUtils.defaultString(draft.vulnerableSnippet()));
		mav.addObject("ruleName", draft.name());
		mav.addObject("ruleMessage", draft.message());
		mav.addObject("rulePriority", draft.priority());
		mav.addObject("ruleFileExt", StringUtils.defaultString(draft.fileExtension()));
		return mav;
	}

	@Override
	public String validateDraft(RuleDraftData draft) {
		try {
			Pattern.compile(draft.definition());
			return null;
		} catch (PatternSyntaxException e) {
			return "The regular expression does not compile: " + e.getDescription() + ".";
		}
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return RegexModule.REGEX_RULE_DESIGNER_PRIVILEGE_NAME;
	}

}
