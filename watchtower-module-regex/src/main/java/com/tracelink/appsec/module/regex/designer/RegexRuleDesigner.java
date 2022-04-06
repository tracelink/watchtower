package com.tracelink.appsec.module.regex.designer;

import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.regex.RegexModule;
import com.tracelink.appsec.module.regex.model.RegexCustomRuleDto;
import com.tracelink.appsec.module.regex.scanner.RegexBenchmarking;
import com.tracelink.appsec.module.regex.scanner.RegexCallable;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
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

	private List<String> getMatches(String query, String code) {
		if (StringUtils.isBlank(query)) {
			return Arrays.asList("");
		}
		CodeScanReport report;
		try {
			report = getRegexReport(query, code);
		} catch (IOException e) {
			return Arrays.asList("Error: Could not query due to IO Error");
		}

		List<String> scanReport =
				report.getViolations().stream().map(sv -> "Found on line: " + sv.getLineNum())
						.collect(Collectors.toList());
		return scanReport;
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
				"The Regex Rule denotes a violation case to be found. When the regex is found in the Source Code, this is marked as a violation.");
		return help;
	}

	@Override
	public RuleDesignerModelAndView getRuleDesignerModelAndView() {
		return query(defaultQuery, defaultSrc);
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return RegexModule.REGEX_RULE_DESIGNER_PRIVILEGE_NAME;
	}

}
