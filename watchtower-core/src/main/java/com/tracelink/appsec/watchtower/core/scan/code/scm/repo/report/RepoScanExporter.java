package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;

/**
 * Writes a repository scan report as CSV or SARIF 2.1.0. Both carry where each finding is and
 * which rule it broke, never code.
 *
 * @author Watchtower
 */
public final class RepoScanExporter {

	private static final ObjectMapper MAPPER = new ObjectMapper();

	private static final String SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";

	private RepoScanExporter() {
	}

	public static void csv(RepoScanReport report, OutputStream out) throws IOException {
		Writer writer = new OutputStreamWriter(out, StandardCharsets.UTF_8);
		writer.write("repository,branch,commit,rule,severity,file,line,message,new\r\n");
		for (RepoScanReport.Finding f : report.findings()) {
			writer.write(String.join(",", cell(report.repository()), cell(report.branch()),
					cell(report.commitHash()), cell(f.rule()), cell(f.severity()), cell(f.file()),
					String.valueOf(f.line()), cell(f.message()), report.comparison() != null && report.comparison().comparable() ? String.valueOf(f.isNew()) : ""));
			writer.write("\r\n");
		}
		writer.flush();
	}

	public static void sarif(RepoScanReport report, OutputStream out) throws IOException {
		ObjectNode root = MAPPER.createObjectNode().put("$schema", SARIF_SCHEMA)
				.put("version", "2.1.0");
		ObjectNode run = root.putArray("runs").addObject();
		run.putObject("tool").putObject("driver").put("name", "Watchtower");
		ArrayNode results = run.putArray("results");
		for (RepoScanReport.Finding f : report.findings()) {
			ObjectNode result = results.addObject().put("ruleId", f.rule())
					.put("level", level(f.severity()));
			result.putObject("message").put("text", f.message() == null ? f.rule() : f.message());
			ObjectNode location = result.putArray("locations").addObject()
					.putObject("physicalLocation");
			location.putObject("artifactLocation").put("uri", f.file());
			if (f.line() > 0) {
				location.putObject("region").put("startLine", f.line());
			}
			result.putObject("partialFingerprints").put("watchtower/v1", f.fingerprint());
		}
		MAPPER.writerWithDefaultPrettyPrinter().writeValue(out, root);
	}

	/**
	 * Quotes a CSV cell, and defuses values a spreadsheet would run as a formula.
	 */
	public static String cell(String value) {
		String text = value == null ? "" : value;
		if (!text.isEmpty() && ("\t\r\n".indexOf(text.charAt(0)) >= 0 || !text.stripLeading().isEmpty() && "=+-@".indexOf(text.stripLeading().charAt(0)) >= 0)) {
			text = "'" + text;
		}
		return "\"" + text.replace("\"", "\"\"") + "\"";
	}

	static String level(String severity) {
		RulePriority priority = RulePriority.priorityForName(severity);
		if (priority == null) {
			return "warning";
		}
		return switch (priority) {
			case HIGH, MEDIUM_HIGH -> "error";
			case MEDIUM, MEDIUM_LOW -> "warning";
			default -> "note";
		};
	}
}
