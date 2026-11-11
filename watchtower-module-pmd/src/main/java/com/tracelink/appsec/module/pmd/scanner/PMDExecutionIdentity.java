package com.tracelink.appsec.module.pmd.scanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDRuleDto;
import com.tracelink.appsec.module.pmd.service.PMDRuleService;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;
import com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity;
import com.tracelink.appsec.watchtower.core.scan.code.JavaEngineExecutionIdentity;

import net.sourceforge.pmd.PmdAnalysis;
import net.sourceforge.pmd.lang.LanguageRegistry;
import net.sourceforge.pmd.lang.rule.Rule;
import net.sourceforge.pmd.lang.rule.RuleReference;
import net.sourceforge.pmd.lang.rule.xpath.XPathRule;
import net.sourceforge.pmd.properties.PropertyDescriptor;

/** Source-free runtime, catalog and resolved-rule evidence for the bundled PMD engine. */
final class PMDExecutionIdentity {
	private static final String ENGINE = "pmd";
	private static final Set<String> RESOURCE_PREFIXES = Set.of("category/", "rulesets/", "rules/",
			"net/sourceforge/pmd/", "net/sf/saxon/", "org/xmlresolver/", "org/antlr/", "scala/",
			"library.properties", "ruleset_2_0_0.dtd", "ruleset_2_0_0.xsd", "META-INF/services/");
	private static final Set<String> XML_LIMITS = Set.of("jdk.xml.maxXMLNameLimit",
			"jdk.xml.entityExpansionLimit", "jdk.xml.totalEntitySizeLimit", "jdk.xml.maxGeneralEntitySizeLimit",
			"jdk.xml.maxParameterEntitySizeLimit", "jdk.xml.elementAttributeLimit", "jdk.xml.maxOccurLimit",
			"jdk.xml.entityReplacementLimit", "jdk.xml.maxElementDepth", "jdk.xml.xpathExprGrpLimit",
			"jdk.xml.xpathExprOpLimit", "jdk.xml.xpathTotalOpLimit");

	private PMDExecutionIdentity() {}

	static EngineExecutionIdentity capture(PMDScanner scanner, PMDRuleService service, CodeScanConfig config) {
		try {
			if (scanner.getClass() != PMDScanner.class || service.getClass() != PMDRuleService.class
					|| config.getRuleset() == null) return EngineExecutionIdentity.unknown(ENGINE);
			if (Thread.currentThread().getContextClassLoader() != PmdAnalysis.class.getClassLoader()) {
				return EngineExecutionIdentity.unknown(ENGINE);
			}
			// Arbitrary installed rule/provider extensions can read settings outside this contract.
			List<String> rules = new ArrayList<>();
			List<Class<?>> anchors = new ArrayList<>(List.of(PMDScanner.class, ICodeScanner.class, PmdAnalysis.class));
			for (var dto : config.getRuleset().getAllRules()) {
				if (!(dto instanceof PMDRuleDto)) continue;
				if (dto instanceof PMDCustomRuleDto custom && !bundled(custom.getRuleClass())) {
					return EngineExecutionIdentity.unknown(ENGINE);
				}
				Rule rule = service.makeRuleFromDto(dto);
				Rule implementation = implementation(rule);
				if (!bundled(rule.getRuleClass()) || !bundled(rule.getClass().getName())
						|| !bundled(implementation.getClass().getName())) {
					return EngineExecutionIdentity.unknown(ENGINE);
				}
				// XPath functions can read external documents, environment or time. Until their
				// dependencies can be certified, only expressions without calls/references opt in.
				if (implementation instanceof XPathRule xpath && (xpath.getXPathExpression().contains("(")
						|| xpath.getXPathExpression().contains("#"))) return EngineExecutionIdentity.unknown(ENGINE);
				anchors.add(rule.getClass());
				anchors.add(implementation.getClass());
				rules.add(RuleRevision.definition(ENGINE, "selected-rule-v1")
						.field("definition", dto.getExecutionIdentity().revision())
						.field("resolved", resolvedRule(rule)).hash());
			}
			List<String> languages = new ArrayList<>();
			for (var language : LanguageRegistry.PMD.getLanguages()) {
				if (!language.getClass().getName().startsWith("net.sourceforge.pmd.lang.")) {
					return EngineExecutionIdentity.unknown(ENGINE);
				}
				anchors.add(language.getClass());
				languages.add(RuleRevision.definition(ENGINE, "language-v1")
						.field("id", language.getId()).field("provider", language.getClass().getName())
						.field("version", language.getDefaultVersion().getVersion())
						.unordered("extensions", language.getExtensions())
						.unordered("dependencies", language.getDependencies()).hash());
			}
			// These overrides can select private catalogs/providers or change parser behavior.
			if (hasXmlOverrides()) return EngineExecutionIdentity.unknown(ENGINE);
			String jaxpDefaults = jaxpConfiguration(Path.of(System.getProperty("java.home"), "conf", "jaxp.properties"));
			var runtime = JavaEngineExecutionIdentity.captureClasspath(ENGINE, scanner, config,
					PmdAnalysis.class.getClassLoader(), RESOURCE_PREFIXES, anchors.stream().distinct().toArray(Class<?>[]::new));
			if (!runtime.isReusable()) return runtime;
			var settings = new PMDScanner.WatchtowerPMDConfiguration(".", config.getThreads());
			String hash = RuleRevision.definition(ENGINE, "pmd-execution-v1")
					.field("runtime", runtime.configurationHash())
					.field("jaxpDefaults", jaxpDefaults)
					.field("encoding", settings.getSourceEncoding().name())
					.field("suppressMarker", settings.getSuppressMarker())
					.field("showSuppressed", Boolean.toString(settings.isShowSuppressedViolations()))
					.field("minimumPriority", settings.getMinimumPriority().name())
					.field("incrementalDisabled", Boolean.toString(settings.isIgnoreIncrementalAnalysis()))
					.unordered("resolvedRules", rules).unordered("languages", languages).hash();
			return new EngineExecutionIdentity(ENGINE, runtime.version(), hash, true);
		} catch (Exception | LinkageError exception) {
			return EngineExecutionIdentity.unknown(ENGINE);
		}
	}

	private static boolean hasXmlOverrides() {
		return System.getProperties().stringPropertyNames().stream().anyMatch(name ->
				name.startsWith("javax.xml.") || name.startsWith("jdk.xml.")
						|| name.startsWith("org.xml.sax.") || name.startsWith("xml.catalog.")
						|| name.startsWith("xmlresolver.") || name.startsWith("saxon.")
						|| name.equals("SAXON_INITIALIZER"))
				|| System.getenv().keySet().stream().anyMatch(name -> name.startsWith("XML_CATALOG_")
						|| name.startsWith("XMLRESOLVER_"))
				|| PmdAnalysis.class.getClassLoader().getResource("xmlresolver.properties") != null;
	}

	/** Capture only public parser limits; private provider/catalog settings remain unsupported. */
	static String jaxpConfiguration(Path jaxp) throws IOException {
		var settings = RuleRevision.definition(ENGINE, "jaxp-defaults-v1");
		if (Files.exists(jaxp)) {
			var overrides = new Properties();
			try (var input = Files.newInputStream(jaxp)) {
				overrides.load(input);
			}
			for (String name : overrides.stringPropertyNames()) {
				String value = overrides.getProperty(name);
				if (XML_LIMITS.contains(name)) {
					long limit = Long.parseLong(value);
					if (limit < 0) throw new IOException("Unsupported XML limit");
					settings.field(name, Long.toString(limit));
				} else if (name.equals("jdk.xml.overrideDefaultParser") && value.equals("false")) {
					settings.field(name, "false");
				} else {
					throw new IOException("Unsupported XML configuration");
				}
			}
		}
		return settings.hash();
	}

	private static boolean bundled(String name) {
		return name != null && (name.startsWith("net.sourceforge.pmd.lang.")
				|| name.startsWith("com.tracelink.appsec.module.pmd.rules."));
	}

	private static Rule implementation(Rule rule) {
		while (rule instanceof RuleReference reference) rule = reference.getRule();
		return rule;
	}

	private static String resolvedRule(Rule rule) {
		RuleRevision definition = RuleRevision.definition(ENGINE, "resolved-rule-v1")
				.field("name", rule.getName()).field("class", rule.getRuleClass())
				.field("language", rule.getLanguage().getId())
				.field("minimumVersion", rule.getMinimumLanguageVersion() == null ? null : rule.getMinimumLanguageVersion().getVersion())
				.field("maximumVersion", rule.getMaximumLanguageVersion() == null ? null : rule.getMaximumLanguageVersion().getVersion())
				.field("priority", rule.getPriority().name()).field("message", rule.getMessage());
		if (implementation(rule) instanceof XPathRule xpath) definition.field("xpath", xpath.getXPathExpression());
		for (PropertyDescriptor<?> descriptor : rule.getPropertyDescriptors()) {
			definition.field("property:" + descriptor.name(), property(rule, descriptor));
		}
		return definition.hash();
	}

	private static <T> String property(Rule rule, PropertyDescriptor<T> descriptor) {
		return descriptor.serializer().toString(rule.getProperty(descriptor));
	}
}
