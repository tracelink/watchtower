package com.tracelink.appsec.module.betterleaks.engine;

import java.util.Collections;
import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Parses the {@code --report-format json} output of {@code betterleaks dir}.
 *
 * @author Watchtower
 */
public class BetterleaksReportParser {

	private static final ObjectMapper MAPPER = new ObjectMapper();

	private static final TypeReference<List<BetterleaksFinding>> FINDINGS =
			new TypeReference<>() {
			};

	private static final TypeReference<List<BetterleaksValidation>> VALIDATIONS =
			new TypeReference<>() {
			};

	/**
	 * @param stdout the report Betterleaks wrote to stdout
	 * @return the findings; empty for a clean scan, which Betterleaks prints as {@code null}
	 * @throws BetterleaksScanException if the report is not the expected JSON, or a finding lacks
	 *                                  its rule or file
	 */
	public List<BetterleaksFinding> parse(String stdout) throws BetterleaksScanException {
		List<BetterleaksFinding> findings = read(stdout, FINDINGS);
		for (BetterleaksFinding finding : findings) {
			requireLocation(finding == null ? null : finding.ruleId(),
					finding == null ? null : finding.file());
		}
		return findings;
	}

	/**
	 * @param stdout the report of a {@code --validation} run
	 * @return each finding with its validation status
	 * @throws BetterleaksScanException as {@link #parse(String)}
	 */
	public List<BetterleaksValidation> parseValidations(String stdout)
			throws BetterleaksScanException {
		List<BetterleaksValidation> validations = read(stdout, VALIDATIONS);
		for (BetterleaksValidation validation : validations) {
			requireLocation(validation == null ? null : validation.ruleId(),
					validation == null ? null : validation.file());
		}
		return validations;
	}

	private static <T> List<T> read(String stdout, TypeReference<List<T>> type)
			throws BetterleaksScanException {
		if (StringUtils.isBlank(stdout)) {
			return List.of();
		}
		List<T> values;
		try {
			values = MAPPER.readValue(stdout, type);
		} catch (JsonProcessingException e) {
			// Not chained: Jackson's message quotes the input, which may hold a secret.
			throw new BetterleaksScanException(BetterleaksScanException.Reason.UNREADABLE_OUTPUT,
					"betterleaks output was unreadable JSON");
		}
		// Not List.copyOf: it would throw on a null element before requireLocation can report it.
		return values == null ? List.of() : Collections.unmodifiableList(values);
	}

	private static void requireLocation(String ruleId, String file)
			throws BetterleaksScanException {
		if (StringUtils.isAnyBlank(ruleId, file)) {
			throw new BetterleaksScanException(BetterleaksScanException.Reason.UNREADABLE_OUTPUT,
					"betterleaks reported a finding without a rule id or file");
		}
	}
}
