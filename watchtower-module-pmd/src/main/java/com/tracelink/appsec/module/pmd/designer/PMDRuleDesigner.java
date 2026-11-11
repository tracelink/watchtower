package com.tracelink.appsec.module.pmd.designer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.module.pmd.scanner.PMDReport;
import com.tracelink.appsec.module.pmd.service.PMDLanguageSupport;
import com.tracelink.appsec.watchtower.core.module.designer.DesignerMatch;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

import net.sourceforge.pmd.PMDConfiguration;
import net.sourceforge.pmd.PmdAnalysis;
import net.sourceforge.pmd.lang.Language;
import net.sourceforge.pmd.lang.LanguageProcessor;
import net.sourceforge.pmd.lang.PmdCapableLanguage;
import net.sourceforge.pmd.lang.LanguageRegistry;
import net.sourceforge.pmd.lang.ast.Node;
import net.sourceforge.pmd.lang.document.FileId;
import net.sourceforge.pmd.lang.document.TextFile;
import net.sourceforge.pmd.lang.rule.AbstractRule;
import net.sourceforge.pmd.lang.rule.RuleSet;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;
import net.sourceforge.pmd.lang.rule.xpath.XPathRule;
import net.sourceforge.pmd.lang.rule.xpath.XPathVersion;
import net.sourceforge.pmd.reporting.Report;
import net.sourceforge.pmd.reporting.RuleContext;

/**
 * The Designer implementation for all PMD languages
 *
 * @author csmith, mcool
 */
@Service
public class PMDRuleDesigner implements IRuleDesigner {
	private static final Logger LOG = LoggerFactory.getLogger(PMDRuleDesigner.class);

	/** Written for the PMD 7 Java AST, where System.out.println is MethodCall/FieldAccess/ClassType. */
	private final String defaultQuery =
			"//MethodCall[@MethodName = \"println\"][FieldAccess[@Name = \"out\"]/TypeExpression/ClassType[@SimpleName = \"System\"]]";

	private final String defaultLanguage = "Java";

	private final String defaultSrc =
			"public class HelloWorld {\n" + "    public static void main(String[] args) {\n"
					+ "        System.out.println(\"Hello, World\");\n" + "    }\n" + "}";

	private final List<String> supportedLanguages = PMDLanguageSupport.getSupportedLanguageNames();

	/**
	 * Run a query for this language on the supplied code and return a new Designer view of the
	 * result
	 *
	 * @param language the PMD language
	 * @param query    the query for the PMD language
	 * @param code     the code to test the query on
	 * @return a new Designer view for the result
	 */
	public RuleDesignerModelAndView query(String language, String query, String code) {
		RuleDesignerModelAndView mav = getBaseMAV();
		queryInternal(mav, language, query, code);
		return mav;
	}

	/** The drafted XPath, already run on the drafted example, with the save dialog's fields filled in. */
	@Override
	public RuleDesignerModelAndView getPrefilledRuleDesignerModelAndView(RuleDraftData draft) {
		String language = languageOf(draft);
		RuleDesignerModelAndView mav = query(language, draft.definition(), StringUtils.defaultString(draft.vulnerableSnippet()));
		mav.addObject("ruleName", draft.name());
		mav.addObject("ruleMessage", draft.message());
		mav.addObject("ruleLanguage", language);
		mav.addObject("rulePriority", draft.priority());
		return mav;
	}

	/** An XPath PMD cannot run, or a language it does not have, is refused before the draft is stored. */
	@Override
	public String validateDraft(RuleDraftData draft) {
		String language = languageOf(draft);
		if (!supportedLanguages.contains(language)) {
			return "PMD does not support " + language + ".";
		}
		return xpathProblem(language, draft.definition());
	}

	/**
	 * Starting the rule is what makes PMD parse the XPath; a query it cannot parse fails here, not
	 * in a report (where it would read as "no matches").
	 *
	 * @return why PMD cannot use the XPath, or null when it can
	 */
	private String xpathProblem(String language, String query) {
		Language lang = LanguageRegistry.PMD.getLanguageByFullName(language);
		XPathRule xpath = new XPathRule(XPathVersion.DEFAULT, query);
		xpath.setLanguage(lang);
		xpath.setDescription("");
		xpath.setMessage("");
		try (LanguageProcessor processor = ((PmdCapableLanguage) lang).createProcessor(lang.newPropertyBundle())) {
			xpath.initialize(processor);
			return null;
		} catch (Exception e) {
			LOG.debug("A drafted XPath did not start", e);
			// "net.sf.saxon.trans.XPathException: Expected ..." is the library talking; keep what it says
			String said = StringUtils.substringBefore(String.valueOf(e.getMessage()), "\n")
					.replaceFirst("^(?:[\\w$]+\\.)+[\\w$]*Exception:\\s*", "");
			return "PMD could not use the XPath: " + StringUtils.abbreviate(said, 160);
		}
	}

	private String languageOf(RuleDraftData draft) {
		return StringUtils.isBlank(draft.language()) ? defaultLanguage : supportedLanguages.stream()
				.filter(name -> name.equalsIgnoreCase(draft.language().strip())).findFirst().orElse(draft.language().strip());
	}

	private void queryInternal(RuleDesignerModelAndView mav, String language, String query,
			String code) {
		mav.addObject("language", language);
		mav.addObject("query", query);
		mav.addObject("sourceCode", code);
		try {
			if (!supportedLanguages.contains(language)) {
				throw new RuleDesignerException("Unsupported Language");
			}
			mav.addObject("matches", getMatches(language, query, code));
			mav.addObject("ast", getPMDAST(language, code));
		} catch (RuleDesignerException e) {
			LOG.error("Exception while getting default model for PMD", e);
			mav.addErrorMessage(e.getMessage());
		}
	}

	private RuleDesignerModelAndView getBaseMAV() {
		RuleDesignerModelAndView mav = new RuleDesignerModelAndView("designer/pmd");
		mav.addObject("supportedLanguages", supportedLanguages);
		mav.addObject("help", getHelp());
		mav.addObject("rulePriorities", RulePriority.values());
		mav.addScriptReference("/scripts/pmd-designer.js");
		return mav;
	}

	private List<DesignerMatch> getMatches(String language, String query, String code)
			throws RuleDesignerException {

		if (StringUtils.isBlank(query)) {
			return List.of();
		}
		String problem = xpathProblem(language, query);
		if (problem != null) {
			return List.of(DesignerMatch.note(problem));
		}

		PMDReport report = getPMDXPathReport(language, query, code);
		if (!report.getErrors().isEmpty()) {
			throw new RuleDesignerException(report.getErrors().get(0).getErrorMessage());
		}
		return report.getViolations().stream()
				.map(sv -> DesignerMatch.atLine(sv.getLineNum(), "Selected by the XPath query"))
				.collect(Collectors.toList());
	}

	/**
	 * Parses the given source into an AST using a throwaway {@link AbstractRule} that simply
	 * captures the root node it's handed, then walks it with {@link PMDASTGenerator}.
	 *
	 * <p>
	 * PMD 6's direct parser invocation ({@code LanguageVersionHandler.getParser(...).parse(...)})
	 * has no equivalent in PMD 7 that doesn't require hand-assembling several internal-ish
	 * classes ({@code LanguageProcessorRegistry}, {@code TextDocument}, {@code ParserTask}).
	 * Instead, this runs a full (if trivial) {@link PmdAnalysis}, the same well-exercised
	 * embedding API {@link #getPMDXPathReport} and {@code PMDScanner} both already use, and lets
	 * PMD's own engine do the parsing.
	 *
	 * <p>
	 * The captured root is stashed in a static field on {@link ASTCapturingRule} - see that
	 * class's javadoc for why. This method is {@code synchronized} because of that shared static
	 * field: only one AST capture may be in flight at a time.
	 */
	private synchronized List<DesignerASTModel> getPMDAST(String language, String code)
			throws RuleDesignerException {
		Language lang = LanguageRegistry.PMD.getLanguageByFullName(language);

		ASTCapturingRule.CAPTURED_ROOT.set(null);

		ASTCapturingRule captureRule = new ASTCapturingRule();
		captureRule.setLanguage(lang);
		captureRule.setName("ASTCapture");
		captureRule.setMessage("");

		PMDConfiguration pmdConfig = new PMDConfiguration();
		pmdConfig.setIgnoreIncrementalAnalysis(true);

		Report report;
		try (PmdAnalysis pmd = PmdAnalysis.create(pmdConfig)) {
			pmd.files().addFile(TextFile.forCharSeq(code,
					FileId.fromPathLikeString("designer." + lang.getExtensions().get(0)),
					lang.getDefaultVersion()));
			pmd.addRuleSet(RuleSet.forSingleRule(captureRule));
			report = pmd.performAnalysisAndCollectReport();
		}

		Node capturedRoot = ASTCapturingRule.CAPTURED_ROOT.get();
		if (capturedRoot == null) {
			LOG.error("Unable to parse source code. Processing errors: {}, Configuration errors: {}",
					report.getProcessingErrors(), report.getConfigurationErrors());
			throw new RuleDesignerException("Unable to parse source code");
		}

		List<DesignerASTModel> designerNodes = new ArrayList<>();
		// Real non-breaking spaces: the view escapes node text, so an "&nbsp;" entity would show literally.
		final String prefixStr = "\u00A0\u00A0";

		new PMDASTGenerator(prefixStr).visit(capturedRoot, "",
				((node, data) -> designerNodes.add(new DesignerASTModel((String) data, node))));

		return designerNodes;
	}

	/**
	 * Runs a single ad-hoc XPath rule against the given source and returns the resulting report.
	 * Reuses {@link PMDReport}'s existing translation from a PMD {@link Report}, same as
	 * {@code PMDScanner}.
	 */
	private PMDReport getPMDXPathReport(String language, String query, String code) {
		return new PMDReport(runXPath(language, query, code), null);
	}

	private Report runXPath(String language, String query, String code) {
		Language lang = LanguageRegistry.PMD.getLanguageByFullName(language);

		XPathRule xpath = new XPathRule(XPathVersion.DEFAULT, query);
		xpath.setLanguage(lang);
		xpath.setDescription("");
		xpath.setMessage("");

		PMDConfiguration pmdConfig = new PMDConfiguration();
		pmdConfig.setIgnoreIncrementalAnalysis(true);

		Report report;
		try (PmdAnalysis pmd = PmdAnalysis.create(pmdConfig)) {
			pmd.files().addFile(TextFile.forCharSeq(code,
					FileId.fromPathLikeString("designer." + lang.getExtensions().get(0)),
					lang.getDefaultVersion()));
			pmd.addRuleSet(RuleSet.forSingleRule(xpath));
			report = pmd.performAnalysisAndCollectReport();
		}

		return report;
	}

	/**
	 * A minimal {@link AbstractRule} whose only purpose is to capture the root AST node PMD hands
	 * it, so the designer can walk it with {@link PMDASTGenerator}.
	 *
	 * <p>
	 * The captured node is stored in a <b>static</b> field on this class, not an instance field:
	 * confirmed via bytecode that {@code Rule.deepCopy()} - which PMD calls before invoking any
	 * rule - constructs a brand new instance via reflection ({@code getDeclaredConstructor().newInstance()}),
	 * copying only the standard {@link net.sourceforge.pmd.lang.rule.Rule} interface properties
	 * (name, language, message, etc. via their getters/setters). It has no way to know about, and
	 * so never copies, a custom subclass field - whatever {@link #apply} sets on the instance
	 * PMD actually calls is invisible to whatever reference the caller kept. A static field is
	 * shared by construction across the original and any deep copy; correctness against
	 * concurrent designer requests comes from {@link PMDRuleDesigner#getPMDAST} being
	 * {@code synchronized}, since only one such analysis may be in flight at a time.
	 */
	private static final class ASTCapturingRule extends AbstractRule {
		private static final AtomicReference<Node> CAPTURED_ROOT = new AtomicReference<>();

		@Override
		protected RuleTargetSelector buildTargetSelector() {
			// AbstractRule's default target selector does NOT target the root node unless told
			// to - confirmed empirically (this rule's apply() never fired without this).
			return RuleTargetSelector.forRootOnly();
		}

		@Override
		public void apply(Node node, RuleContext ctx) {
			CAPTURED_ROOT.set(node);
		}
	}

	private static Map<String, String> getHelp() {
		Map<String, String> help = new HashMap<String, String>();
		help.put("pmdSource",
				"The Source Code Section is where Rule Designers should put all source code to be tested. It should match the Language dropdown below it.");
		help.put("syntax",
				"The Syntax Tree Section will show the AST of the Source Code once a rule has been run -including an empty rule. Click on each Attribute to show the Attributes associated to each node. These Attributes are available to be scanned via XPath.");
		help.put("xpath",
				"An XPath query over the syntax tree. Each node it selects is a finding. The starter query finds System.out.println calls (1 match on the starter sample). Open Syntax tree to see the PMD 7 node and attribute names.");
		help.put("matches",
				"The Match Section shows whether any values were found for the query and source code.");
		return help;
	}

	@Override
	public RuleDesignerModelAndView getDefaultRuleDesignerModelAndView() {
		RuleDesignerModelAndView mav = getBaseMAV();
		queryInternal(mav, defaultLanguage, defaultQuery, defaultSrc);
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return PMDModule.PMD_RULE_DESIGNER_PRIVILEGE_NAME;
	}

}
