package com.tracelink.appsec.module.json.designer;

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

import com.tracelink.appsec.module.json.JsonModule;
import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.module.json.scanner.JsonCallable;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * The Designer implementation for JSON
 *
 * @author csmith
 */
@Service
public class JsonRuleDesigner implements IRuleDesigner {

	private final String defaultJson = "{\n" +
			"  \"type\": \"person\",\n" +
			"  \"people\": [\n" +
			"    {\n" +
			"      \"name\": \"Fred\",\n" +
			"      \"age\": 23\n" +
			"    },\n" +
			"    {\n" +
			"      \"name\": \"Alex\",\n" +
			"      \"age\": 53\n" +
			"    },\n" +
			"    {\n" +
			"      \"name\": \"James\",\n" +
			"      \"age\": 39\n" +
			"    }\n" +
			"  ]\n" +
			"}";

	private final String defaultQuery = "$.people.*.[?(@.age>45)]";

	@Override
	public RuleDesignerModelAndView getRuleDesignerModelAndView() {
		return query(defaultQuery, defaultJson);
	}

	/**
	 * Execute a query using the given query and code and return its result
	 *
	 * @param query the JsonPath query
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
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView("designer/json");
		mav.addObject("rulePriorities", RulePriority.values());
		mav.addObject("help", getHelp());
		mav.addScriptReference("/scripts/json-designer.js");
		return mav;
	}

	private void queryInternal(RuleDesignerModelAndView mav, String query, String code) {
		mav.addObject("query", query);
		mav.addObject("code", code);
		mav.addObject("matches", getMatches(query, code));
	}

	private List<String> getMatches(String query, String code) {
		if (StringUtils.isBlank(query)) {
			return Arrays.asList("");
		}
		List<String> matches;
		try {
			ScanReport report = getReport(query, code);
			matches = report.getViolations().stream().map(sv -> "Found on line: " + sv.getLineNum())
					.collect(Collectors.toList());
		} catch (IOException e) {
			matches = Arrays.asList(e.getMessage());
		}
		return matches;
	}

	private ScanReport getReport(String query, String code) throws IOException {
		Path temp = Files.createTempFile(null, null);
		try (FileWriter fw = new FileWriter(temp.toFile())) {
			fw.write(code);
		}

		JsonRuleDto rule = new JsonRuleDto();
		rule.setName("Test Rule");
		rule.setPriority(RulePriority.LOW);
		rule.setQuery(query);
		rule.setFileExtension("");
		RulesetDto ruleset = new RulesetDto();
		ruleset.setRules(Collections.singleton(rule));

		JsonCallable json = new JsonCallable(temp, ruleset);
		ScanReport report = json.call();
		FileUtils.deleteQuietly(temp.toFile());
		return report;
	}

	private static Map<String, String> getHelp() {
		Map<String, String> help = new HashMap<>();
		help.put("jsonSource",
				"The Source Code Section is where Rule Designers should put all source code to be tested.");
		help.put("json",
				"The JSON Rule is a JSONPath expression used to identify elements within a JSON snippet. When the JSONPath expression is found in the source code, it is marked as a violation.");
		help.put("matches",
				"The Matches section shows the line numbers of any violations that were found in the source code.");
		return help;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return JsonModule.JSON_RULE_DESIGNER_PRIVILEGE_NAME;
	}
}
