package com.tracelink.appsec.module.json.designer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

import com.jayway.jsonpath.JsonPath;

import com.tracelink.appsec.module.json.JsonModule;
import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.module.json.scanner.JsonCallable;
import com.tracelink.appsec.watchtower.core.module.designer.DesignerMatch;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

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
	public RuleDesignerModelAndView getDefaultRuleDesignerModelAndView() {
		return query(defaultQuery, defaultJson);
	}

	/** The drafted JSONPath, already run on the drafted example, with the save dialog's fields filled in. */
	@Override
	public RuleDesignerModelAndView getPrefilledRuleDesignerModelAndView(RuleDraftData draft) {
		RuleDesignerModelAndView mav = query(draft.definition(), StringUtils.defaultString(draft.vulnerableSnippet()), formatOf(draft));
		mav.addObject("ruleName", draft.name());
		mav.addObject("ruleMessage", draft.message());
		mav.addObject("rulePriority", draft.priority());
		mav.addObject("ruleFileExt", StringUtils.defaultString(draft.fileExtension()));
		return mav;
	}

	@Override
	public String validateDraft(RuleDraftData draft) {
		try {
			JsonPath.compile(draft.definition());
			return null;
		} catch (RuntimeException e) {
			return "The JSONPath query is not valid.";
		}
	}

	/** YAML when the draft says so; anything else is JSON. */
	private static String formatOf(RuleDraftData draft) {
		return "yaml".equalsIgnoreCase(StringUtils.trimToEmpty(draft.language())) ? "yaml" : "json";
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
		return query(query, code, "json");
    }

    public RuleDesignerModelAndView query(String query, String code, String sourceFormat) {
        if (!java.util.Set.of("json", "yaml").contains(sourceFormat)) throw new IllegalArgumentException("Unsupported source format");
        RuleDesignerModelAndView mav = getBaseMAV();
        mav.addObject("sourceFormat", sourceFormat);
        queryInternal(mav, query, code, sourceFormat);
		return mav;
	}

	private RuleDesignerModelAndView getBaseMAV() {
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView("designer/json");
		mav.addObject("rulePriorities", RulePriority.values());
		mav.addObject("help", getHelp());
		mav.addScriptReference("/scripts/json-designer.js");
		return mav;
	}

	private void queryInternal(RuleDesignerModelAndView mav, String query, String code, String sourceFormat) {
		mav.addObject("query", query);
		mav.addObject("code", code);
		mav.addObject("matches", getMatches(query, code, sourceFormat));
	}

	private List<DesignerMatch> getMatches(String query, String code, String sourceFormat) {
		if (StringUtils.isBlank(query)) {
			return List.of();
		}
		try {
			JsonPath.compile(query);
		} catch (RuntimeException e) {
			return List.of(DesignerMatch.note("The JSONPath query is not valid."));
		}
		try {
			CodeScanReport report = getReport(query, code, sourceFormat);
			if (!report.getErrors().isEmpty()) {
				return report.getErrors().stream().map(error -> DesignerMatch.note(error.getErrorMessage())).toList();
			}
			// YAML matches say which document they are in ("YAML document 2: "); JSON has one.
			return report.getViolations().stream().map(sv -> DesignerMatch.atLine(sv.getLineNum(),
					sourceFormat.equals("yaml") && sv.getMessage() != null
							? sv.getMessage().replaceAll(":\\s*$", "") : "Selected by the query"))
					.collect(Collectors.toList());
		} catch (IOException e) {
			return List.of(DesignerMatch.note(e.getMessage()));
		}
	}

	private CodeScanReport getReport(String query, String code, String sourceFormat) throws IOException {
		Path temp = Files.createTempFile("configuration-", sourceFormat.equals("yaml") ? ".yaml" : ".json");
		try {
		Files.writeString(temp, code, java.nio.charset.StandardCharsets.UTF_8);

		JsonRuleDto rule = new JsonRuleDto();
		rule.setName("Test Rule");
		rule.setPriority(RulePriority.LOW);
		rule.setQuery(query);
		rule.setFileExtension("");
		RulesetDto ruleset = new RulesetDto();
		ruleset.setRules(Collections.singleton(rule));

		JsonCallable json = new JsonCallable(temp, ruleset);
		CodeScanReport report = json.call();
		return report;
		} finally { Files.deleteIfExists(temp); }
	}

	private static Map<String, String> getHelp() {
		Map<String, String> help = new HashMap<>();
		help.put("jsonSource",
				"The Source Code Section is where Rule Designers should put all source code to be tested.");
		help.put("json",
				"A JSONPath query over JSON or YAML documents. Each node it selects is a finding.");
		help.put("matches",
				"The Matches section shows the line numbers (and YAML document numbers) of any violations that were found in the source code.");
		return help;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return JsonModule.JSON_RULE_DESIGNER_PRIVILEGE_NAME;
	}
}
