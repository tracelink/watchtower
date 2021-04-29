package com.tracelink.appsec.module.pmd.designer;

import java.io.File;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.pmd.PMDModule;
import com.tracelink.appsec.module.pmd.scanner.PMDReport;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

import net.sourceforge.pmd.PMD;
import net.sourceforge.pmd.PMDException;
import net.sourceforge.pmd.Report;
import net.sourceforge.pmd.RuleContext;
import net.sourceforge.pmd.RuleSet;
import net.sourceforge.pmd.RuleSets;
import net.sourceforge.pmd.RulesetsFactoryUtils;
import net.sourceforge.pmd.lang.Language;
import net.sourceforge.pmd.lang.LanguageRegistry;
import net.sourceforge.pmd.lang.LanguageVersionHandler;
import net.sourceforge.pmd.lang.ast.Node;
import net.sourceforge.pmd.lang.ast.ParseException;
import net.sourceforge.pmd.lang.rule.XPathRule;

/**
 * The Designer implementation for all PMD languages
 *
 * @author csmith, mcool
 */
@Service
public class PMDRuleDesigner implements IRuleDesigner {
	private static final Logger LOG = LoggerFactory.getLogger(PMDRuleDesigner.class);

	private final String defaultQuery =
			"//PrimaryPrefix[Name[starts-with(@Image,\"System.out\")]]";

	private final String defaultLanguage = "Java";

	private final String defaultSrc =
			"public class HelloWorld {\n" + "    public static void main(String[] args) {\n"
					+ "        System.out.println(\"Hello, World\");\n" + "    }\n" + "}";

	private final List<String> supportedLanguages =
			Arrays.asList("Java", "Ecmascript", "Scala", "XML");

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
		} catch (RuleDesignerException | PMDException e) {
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

	private List<String> getMatches(String language, String query, String code)
			throws RuleDesignerException, PMDException {

		if (StringUtils.isBlank(query)) {
			return Arrays.asList("");
		}

		PMDReport report = getPMDXPathReport(language, query, code);
		List<String> scanReport =
				report.getViolations().stream().map(sv -> "Found on line: " + sv.getLineNum())
						.collect(Collectors.toList());
		return scanReport;
	}

	private List<DesignerASTModel> getPMDAST(String language, String code)
			throws RuleDesignerException, ParseException {
		Language lang = LanguageRegistry.getLanguage(language);
		LanguageVersionHandler lvh = lang.getDefaultVersion().getLanguageVersionHandler();
		Node root = lvh.getParser(lvh.getDefaultParserOptions()).parse("",
				new StringReader(code));

		List<DesignerASTModel> designerNodes = new ArrayList<>();
		final String prefixStr = "&nbsp;";

		new PMDASTGenerator(prefixStr).visit(root, "",
				((node, data) -> designerNodes.add(new DesignerASTModel((String) data, node))));

		return designerNodes;
	}

	private PMDReport getPMDXPathReport(String language, String query, String code)
			throws PMDException {
		Language lang = LanguageRegistry.getLanguage(language);

		XPathRule xpath = new XPathRule();
		xpath.setLanguage(lang);
		xpath.setDescription("");
		xpath.setMessage("");
		xpath.setXPath(query);
		PMD p = new PMD();
		RuleContext ctx = new RuleContext();
		Report report = new Report();
		ctx.setReport(report);
		ctx.setSourceCodeFile(new File("foobar." + lang.getExtensions().get(0)));
		RuleSet rules = RulesetsFactoryUtils.defaultFactory().createSingleRuleRuleSet(xpath);
		p.getSourceCodeProcessor().processSourceCode(new StringReader(code),
				new RuleSets(rules), ctx);

		return new PMDReport(report, null);
	}

	private static Map<String, String> getHelp() {
		Map<String, String> help = new HashMap<String, String>();
		help.put("pmdSource",
				"The Source Code Section is where Rule Designers should put all source code to be tested. It should match the Language dropdown below it.");
		help.put("syntax",
				"The Syntax Tree Section will show the AST of the Source Code once a rule has been run -including an empty rule. Click on each Attribute to show the Attributes associated to each node. These Attributes are available to be scanned via XPath.");
		help.put("xpath",
				"The XPath Rule denotes a violation case in the Syntax Tree. When the XPath resolves to a Node in the AST, this is marked as a violation.");
		help.put("matches",
				"The Match Section shows whether any values were found for the query and source code.");
		return help;
	}

	@Override
	public RuleDesignerModelAndView getRuleDesignerModelAndView() {
		RuleDesignerModelAndView mav = getBaseMAV();
		queryInternal(mav, defaultLanguage, defaultQuery, defaultSrc);
		return mav;
	}

	@Override
	public String getPrivilegeNameForAccess() {
		return PMDModule.PMD_RULE_DESIGNER_PRIVILEGE_NAME;
	}

}
