package com.tracelink.appsec.module.eslint.designer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.logging.log4j.util.Strings;
import org.springframework.stereotype.Service;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.tracelink.appsec.module.eslint.EsLintModule;
import com.tracelink.appsec.module.eslint.engine.LinterEngine;
import com.tracelink.appsec.module.eslint.engine.ProcessResult;
import com.tracelink.appsec.module.eslint.engine.json.LinterMessage;
import com.tracelink.appsec.module.eslint.model.EsLintCustomRuleDto;
import com.tracelink.appsec.module.eslint.model.EsLintMessageDto;
import com.tracelink.appsec.module.eslint.model.EsLintRuleDto;
import com.tracelink.appsec.module.eslint.scanner.EsLintScanner;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

/**
 * Implementation of the {@link IRuleDesigner} for ESLint rules. Allows querying against custom
 * ESLint rules.
 *
 * @author mcool
 */
@Service
public class EsLintRuleDesigner implements IRuleDesigner {

	public static final String DEFAULT_NAME = "Example Rule";

	public static final String DEFAULT_SOURCE_CODE = "if (foo == null) {\n"
			+ "  bar();\n"
			+ "}\n"
			+ "\n"
			+ "while (qux != null) {\n"
			+ "  baz();\n"
			+ "}";

	public static final String DEFAULT_CREATE_FUNCTION = "create(context) {\n"
			+ "    return {\n"
			+ "        BinaryExpression(node) {\n"
			+ "            const badOperator = node.operator === \"==\" || node.operator === \"!=\";\n"
			+ "\n"
			+ "            if (node.right.type === \"Literal\" && node.right.raw === \"null\" && badOperator ||\n"
			+ "                    node.left.type === \"Literal\" && node.left.raw === \"null\" && badOperator) {\n"
			+ "                context.report({ node, messageId: \"unexpected\" });\n"
			+ "            }\n"
			+ "        }\n"
			+ "    };\n"
			+ "}";

	public static final String DEFAULT_MESSAGE_KEY = "unexpected";
	public static final String DEFAULT_MESSAGE_VALUE = "Use '===' to compare with null.";
	private static final String DEFAULT_MESSAGE = "Example Message";
	private static final String DEFAULT_URL = "https://example.com";

	private static final List<EsLintMessageDto> DEFAULT_MESSAGES = Collections
			.singletonList(new EsLintMessageDto(DEFAULT_MESSAGE_KEY, DEFAULT_MESSAGE_VALUE));

	private static final String CANNOT_PARSE_SOURCE_CODE = "Cannot parse source code";
	private static final Gson GSON = new GsonBuilder().setPrettyPrinting().create();


	private final EsLintScanner scanner;

	private final LinterEngine engine;

	public EsLintRuleDesigner(LinterEngine engine) {
		this.scanner = new EsLintScanner(engine);
		this.engine = engine;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public RuleDesignerModelAndView getDefaultRuleDesignerModelAndView() {
		EsLintCustomRuleDto rule = new EsLintCustomRuleDto();
		rule.setCreateFunction(DEFAULT_CREATE_FUNCTION);
		rule.setMessages(DEFAULT_MESSAGES);
		return query(DEFAULT_SOURCE_CODE, DEFAULT_CREATE_FUNCTION, DEFAULT_MESSAGES);
	}

	/**
	 * Scans the given source code using a single ESLint rule. Constructs the ESLint rule from the
	 * given parameters. Stores all given values in the returned ModelAndView to maintain state
	 * while designing.
	 *
	 * @param sourceCode     source code to test the rule against
	 * @param createFunction createFunction of the rule
	 * @param messages       messages of the rule
	 * @return ModelAndView to display AST of source code and any scan violations to the user
	 */
	public RuleDesignerModelAndView query(String sourceCode, String createFunction,
			List<EsLintMessageDto> messages) {
		// Create rule to scan with
		EsLintCustomRuleDto rule;
		try {
			rule = createRule(createFunction, messages);
		} catch (RuleDesignerException e) {
			RuleDesignerModelAndView mav = getBaseModelAndView();
			mav.addErrorMessage(e.getMessage());
			return mav;
		}
		return query(sourceCode, rule);

	}

	/**
	 * Scans the given source code using a single ESLint rule. Stores all given values in the
	 * returned ModelAndView to maintain state while designing.
	 *
	 * @param sourceCode source code to test the rule against
	 * @param rule       the ESLint Rule to use
	 * @return ModelAndView to display AST of source code and any scan violations to the user
	 */
	public RuleDesignerModelAndView query(String sourceCode, EsLintCustomRuleDto rule) {
		// Build ModelAndView
		RuleDesignerModelAndView mav = getBaseModelAndView();
		mav.addObject("rule", rule);
		mav.addObject("sourceCode", sourceCode);

		if (!isValidQueryRule(sourceCode, rule, mav)) {
			return mav;
		}

		// Add AST for source code and any parsing errors
		addAst(mav, sourceCode);

		// Add matches and any errors from scan
		addMatches(mav, rule, sourceCode);

		return mav;
	}


	private boolean isValidQueryRule(String sourceCode, EsLintCustomRuleDto rule,
			RuleDesignerModelAndView mav) {
		List<String> errors = new ArrayList<>();
		if (StringUtils.isBlank(sourceCode)) {
			errors.add("Please provide source code to test against the rule.");
		}
		if (StringUtils.isBlank(rule.getCreateFunction())) {
			errors.add("Must provide create function for a custom rule.");
		}
		if (rule.getMessages().stream().anyMatch(
				m -> m == null || StringUtils.isBlank(m.getKey()) || StringUtils
						.isBlank(m.getValue()))) {
			errors.add("Messages for a custom rule must have a valid ID and value.");
		}
		if (!errors.isEmpty()) {
			mav.addErrorMessage(Strings.join(errors, ','));
		}
		return errors.isEmpty();
	}

	/**
	 * Create an ESLint rule from the given parameters to scan source code from the designer.
	 *
	 * @param createFunction createFunction of the rule (used for custom rule)
	 * @param messages       messages of the rule (used for custom rule)
	 * @return an ESLint rule representing the given parameters
	 */
	private EsLintCustomRuleDto createRule(String createFunction, List<EsLintMessageDto> messages)
			throws RuleDesignerException {
		// Create rule to test
		EsLintCustomRuleDto rule = getBaseQueryRule();
		rule.setCreateFunction(createFunction);
		if (messages != null) {
			rule.setMessages(messages);
		}
		rule.setPriority(RulePriority.LOW);
		return rule;
	}

	/**
	 * Parses the given source code and adds the abstract syntax tree to the given
	 * {@link RuleDesignerModelAndView}.
	 *
	 * @param mav        the {@link RuleDesignerModelAndView} that will be returned to the user
	 * @param sourceCode the source code to parse
	 */
	private void addAst(RuleDesignerModelAndView mav, String sourceCode) {
		// Parse the ruleset
		ProcessResult parseResult = engine.parseAst(sourceCode);
		// Check if an error occurred while parsing
		if (parseResult.hasErrors()) {
			mav.addErrorMessage(CANNOT_PARSE_SOURCE_CODE + ": " + parseResult.getErrors());
			return;
		}

		if (parseResult.hasResults()) {
			String results = parseResult.getResults();
			// Check if results contain error messages
			if (results.startsWith("[") && results.endsWith("]")) {
				List<LinterMessage> messages = GSON
						.fromJson(results, LinterEngine.MESSAGES_TYPE_TOKEN.getType());
				mav.addErrorMessage(CANNOT_PARSE_SOURCE_CODE + ": " + messages.get(0).getMessage());
				return;
			}
			// Parse AST and add to MAV
			mav.addObject("ast", GSON.toJson(JsonParser.parseString(results)));
		} else {
			mav.addErrorMessage(CANNOT_PARSE_SOURCE_CODE);
		}
	}

	/**
	 * Scans the given source code with the given rule and adds any violations or errors to the
	 * given {@link RuleDesignerModelAndView}.
	 *
	 * @param mav        the {@link RuleDesignerModelAndView} that will be returned to the user
	 * @param rule       the ESLint rule to scan with
	 * @param sourceCode the source code to scan
	 */
	private void addMatches(RuleDesignerModelAndView mav, EsLintCustomRuleDto rule,
			String sourceCode) {
		RulesetDto ruleset = new RulesetDto();
		ruleset.setName("query-ruleset");
		ruleset.setDescription("query-description");
		ruleset.setRules(Collections.singleton(rule));

		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(ruleset);

		try {
			Path dir = Files.createTempDirectory(null);
			Path file = Files.createTempFile(dir, null, ".js");
			Files.write(file, sourceCode.getBytes());
			config.setWorkingDirectory(dir);
		} catch (IOException e) {
			mav.addErrorMessage("Error while writing source code to file: " + e.getMessage());
			return;
		}

		// Get violations and any errors from scanner
		CodeScanReport report = scanner.scan(config);
		List<String> matches = report.getViolations().stream()
				.map(violation -> "Line " + violation.getLineNum() + ": " + violation.getMessage())
				.collect(Collectors.toList());
		mav.addObject("matches", matches);
		if (!report.getErrors().isEmpty()) {
			mav.addErrorMessage(report.getErrors().get(0).getErrorMessage());
		}
	}

	/**
	 * Constructs a base {@link RuleDesignerModelAndView} to return to the user.
	 *
	 * @return an {@link RuleDesignerModelAndView} with basic fields to render the ESLint designer
	 */
	private RuleDesignerModelAndView getBaseModelAndView() {
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView("designer/eslint");
		mav.addObject("rulePriorities", RulePriority.values());
		mav.addObject("help", getHelp());
		mav.addScriptReference("/scripts/eslint-designer.js");
		return mav;
	}

	/**
	 * Constructs a base {@link EsLintRuleDto} to use for scanning source code from the designer.
	 *
	 * @return an {@link EsLintRuleDto} with mock required fields added
	 */
	private EsLintCustomRuleDto getBaseQueryRule() {
		EsLintCustomRuleDto rule = new EsLintCustomRuleDto();
		rule.setName(DEFAULT_NAME);
		rule.setPriority(RulePriority.LOW);
		rule.setMessage(DEFAULT_MESSAGE);
		rule.setExternalUrl(DEFAULT_URL);
		rule.setMessages(new ArrayList<>());
		return rule;
	}

	/**
	 * Constructs a map of "help" information to display to users on the designer page.
	 *
	 * @return map of "help" strings
	 */
	private static Map<String, String> getHelp() {
		Map<String, String> help = new HashMap<>();
		help.put("sourceCode",
				"The Source Code section stores all source code to be tested against the rule.");
		help.put("ast",
				"The Abstract Syntax Tree section shows the syntax elements of the source code to assist with writing a custom rule.");
		help.put("matches",
				"The Matches section shows any violations that were found for the source code, along with the message that will be displayed to the user.");
		help.put("esLintRule",
				"The ESLint Rule section stores info about a custom rule. "
						+ "If you want to design a rule, provide the JavaScript code for the \"create\" function. ");
		help.put("messages",
				"The Messages section stores message IDs and values for any message IDs defined in the custom rule.");
		return help;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return EsLintModule.ESLINT_RULE_DESIGNER_PRIVILEGE_NAME;
	}
}
