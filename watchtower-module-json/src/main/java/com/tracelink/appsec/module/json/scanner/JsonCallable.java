package com.tracelink.appsec.module.json.scanner;

import java.nio.file.Path;
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
import com.tracelink.appsec.watchtower.core.report.ScanError;
import com.tracelink.appsec.watchtower.core.report.ScanReport;
import com.tracelink.appsec.watchtower.core.report.ScanViolation;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

/**
 * A single Callable that scans a single file for all applicable json rules
 * 
 * @author csmith
 *
 */
public class JsonCallable implements Callable<ScanReport> {
	private static Logger LOG = LoggerFactory.getLogger(JsonCallable.class);

	private final Path currentFile;
	private final RulesetDto ruleset;
	private final Configuration config;
	private final CustomJsonNodeFactory factory;

	/**
	 * The source processor for Json scans.
	 *
	 * @param file    the file this code comes from
	 * @param ruleset the ruleset to use in this scan
	 */
	public JsonCallable(Path file, RulesetDto ruleset) {
		this.currentFile = file;
		this.ruleset = ruleset;
		CustomParserFactory customParserFactory = new CustomParserFactory();
		ObjectMapper om = new ObjectMapper(customParserFactory);
		factory = new CustomJsonNodeFactory(om.getDeserializationConfig().getNodeFactory(),
				customParserFactory);
		om.setConfig(om.getDeserializationConfig().with(factory));
		config = Configuration.builder()
				.mappingProvider(new JacksonMappingProvider(om))
				.jsonProvider(new JacksonJsonNodeJsonProvider(om))
				.options(Option.ALWAYS_RETURN_LIST)
				.build();
	}

	@Override
	public ScanReport call() {
		ScanReport report = new ScanReport();

		DocumentContext parsedDocument = null;

		for (RuleDto rule : ruleset.getAllRules()) {
			if (rule instanceof JsonRuleDto) {
				JsonRuleDto jsonRule = (JsonRuleDto) rule;

				if (jsonRule.isValidExtension(currentFile.toString())) {
					JsonPath jsonPath = jsonRule.getCompiledQuery();

					/*
					 * If any rule wants the file, parse it and set lazily so that subsequent
					 * JsonPath reads and faster
					 */
					if (parsedDocument == null) {
						try {
							parsedDocument = JsonPath.parse(this.currentFile.toFile(), config);
						} catch (Exception e) {
							String errorMsg = "Could not parse the file "
									+ this.currentFile.getFileName() + " as JSON";
							report.addError(new ScanError(errorMsg));
							LOG.error(errorMsg, e);
							return report;
						}
					}
					ArrayNode findings = parsedDocument.read(jsonPath);
					for (JsonNode finding : findings) {
						JsonLocation location = this.factory.getLocationForNode(finding);
						int lineNum = 0;
						if (location != null) {
							lineNum = location.getLineNr();
						} else {
							LOG.error("Could not find location for line");
						}
						ScanViolation sv = new ScanViolation();
						sv.setViolationName(rule.getName());
						sv.setFileName(currentFile.toString());
						sv.setLineNum(lineNum);
						sv.setSeverity(rule.getPriority().getName());
						sv.setSeverityValue(rule.getPriority().getPriority());
						sv.setMessage(rule.getMessage());
						report.addViolation(sv);
					}
				}
			}
		}
		return report;
	}
}
