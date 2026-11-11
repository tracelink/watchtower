package com.tracelink.appsec.module.json.scanner;

import java.nio.file.Path;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import com.tracelink.appsec.module.json.scanner.provider.YamlDocuments;
import java.util.concurrent.Callable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.DocumentContext;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.spi.json.JacksonJsonNodeJsonProvider;
import com.jayway.jsonpath.spi.mapper.JacksonMappingProvider;
import com.tracelink.appsec.module.json.model.JsonRuleDto;
import com.tracelink.appsec.module.json.scanner.provider.CustomJsonNodeFactory;
import com.tracelink.appsec.module.json.scanner.provider.CustomParserFactory;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanError;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;

/**
 * A single Callable that scans a single file for all applicable json rules
 * 
 * @author csmith
 *
 */
public class JsonCallable implements Callable<CodeScanReport> {
	private static Logger LOG = LoggerFactory.getLogger(JsonCallable.class);

	private final Path currentFile;
	private final RulesetDto ruleset;
	private final Configuration config;
	private final CustomJsonNodeFactory factory;
	private final boolean yaml;

	/**
	 * The source processor for Json scans.
	 *
	 * @param file    the file this code comes from
	 * @param ruleset the ruleset to use in this scan
	 */
	public JsonCallable(Path file, RulesetDto ruleset) {
		this.currentFile = file;
		this.ruleset = ruleset;
		String name = file.toString().toLowerCase(Locale.ROOT);
		yaml = name.endsWith(".yaml") || name.endsWith(".yml");
		CustomParserFactory customParserFactory = new CustomParserFactory();
		ObjectMapper om = new ObjectMapper(customParserFactory);
		factory = yaml ? new CustomJsonNodeFactory() : new CustomJsonNodeFactory(om.getDeserializationConfig().getNodeFactory(),
				customParserFactory);
		om.setConfig(om.getDeserializationConfig().with(factory));
		config = Configuration.builder()
				.mappingProvider(new JacksonMappingProvider(om))
				.jsonProvider(new JacksonJsonNodeJsonProvider(om))
				.options(Option.ALWAYS_RETURN_LIST)
				.build();
	}

	@Override
	public CodeScanReport call() {
		CodeScanReport report = new CodeScanReport();

		List<DocumentContext> parsedDocuments = null;

		for (RuleDto rule : ruleset.getAllRules()) {
			if (rule instanceof JsonRuleDto) {
				JsonRuleDto jsonRule = (JsonRuleDto) rule;

				if (jsonRule.isValidExtension(currentFile.toString())) {
					JsonPath jsonPath = jsonRule.getCompiledQuery();

					/*
					 * If any rule wants the file, parse it and set lazily so that subsequent
					 * JsonPath reads and faster
					 */
					if (parsedDocuments == null) {
						try {
							if (yaml) {
								if (Files.size(currentFile) > YamlDocuments.MAX_INPUT_BYTES) throw new IllegalArgumentException("YAML input exceeds limit");
								try (var reader = Files.newBufferedReader(currentFile, StandardCharsets.UTF_8)) {
									parsedDocuments = new YamlDocuments(factory).read(reader).stream().map(n -> JsonPath.parse(n, config)).toList();
								}
							} else parsedDocuments = List.of(JsonPath.parse(this.currentFile.toFile(), config));
						} catch (Exception e) {
							String errorMsg = "Could not parse the file "
									+ this.currentFile.getFileName() + (yaml ? " as YAML" : " as JSON");
							report.addError(new CodeScanError(errorMsg));
							LOG.error("Structured file parsing failed ({})", yaml ? "YAML" : "JSON");
							return report;
						}
					}
					for (int document = 0; document < parsedDocuments.size(); document++) {
					ArrayNode findings;
					try { findings = parsedDocuments.get(document).read(jsonPath); }
					catch (com.jayway.jsonpath.PathNotFoundException absent) { continue; }
					for (JsonNode finding : findings) {
						JsonLocation location = this.factory.getLocationForNode(finding);
						int lineNum = 0;
						if (location != null) {
							lineNum = location.getLineNr();
						} else {
							LOG.error("Could not find location for line");
						}
						CodeScanViolation sv = new CodeScanViolation();
						sv.setRuleIdentity(rule.getExecutionIdentity());
						sv.setViolationName(rule.getName());
						sv.setFileName(currentFile.toString());
						sv.setLineNum(lineNum);
						sv.setSeverity(rule.getPriority());
						sv.setMessage(yaml ? "YAML document " + (document + 1) + ": " + (rule.getMessage() == null ? "" : rule.getMessage()) : rule.getMessage());
						report.addViolation(sv);
					}
				}
				}
			}
		}
		return report;
	}
}
