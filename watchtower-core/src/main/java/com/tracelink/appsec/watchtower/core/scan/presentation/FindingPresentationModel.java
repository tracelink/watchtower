package com.tracelink.appsec.watchtower.core.scan.presentation;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.IntStream;

import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.result.PRScanResultViolation;
import com.tracelink.appsec.watchtower.core.scan.code.upload.result.UploadScanResultViolation;
import com.tracelink.appsec.watchtower.core.scan.image.result.ImageScanResultViolation;

/**
 * Read-only, scan-type-neutral representation of a finding for the report workspace.
 * Domain result objects and REST contracts intentionally remain unchanged.
 */
public final class FindingPresentationModel {
	private com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails providerDetails;
	private String providerDetailUrl;
	public String getProviderDetailUrl() { return providerDetailUrl; }
	public String getSeverityFilterKey() {
		if (providerDetails != null && ("CRITICAL".equals(providerDetails.severity()) || "LOW".equals(providerDetails.severity()) || "UNKNOWN".equals(providerDetails.severity()))) return providerDetails.severity();
		return Integer.toString(severityValue);
	}
	public FindingPresentationModel withProviderDetailUrl(String url) { providerDetailUrl = url; return this; }
	private String reviewJudgment;

	/** The latest saved human judgment (TRUE_POSITIVE, FALSE_POSITIVE, UNKNOWN), or null. */
	public FindingPresentationModel withReview(String judgment) { reviewJudgment = judgment; return this; }

	/** reviewed state for the list marker: unreviewed, true, false or unknown. */
	public String getReviewState() {
		if (reviewJudgment == null) return "unreviewed";
		return switch (reviewJudgment) {
			case "TRUE_POSITIVE" -> "true";
			case "FALSE_POSITIVE" -> "false";
			default -> "unknown";
		};
	}

	public String getReviewIcon() {
		return switch (getReviewState()) {
			case "true" -> "check_circle";
			case "false" -> "cancel";
			case "unknown" -> "help";
			default -> "radio_button_unchecked";
		};
	}

	public String getReviewLabel() {
		return switch (getReviewState()) {
			case "true" -> "Reviewed: true positive";
			case "false" -> "Reviewed: false positive";
			case "unknown" -> "Reviewed: unknown";
			default -> "Not reviewed";
		};
	}
	public static FindingPresentationModel fromRepository(com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReport.Finding finding) {
		var priority = com.tracelink.appsec.watchtower.core.rule.RulePriority.priorityForName(finding.severity());
		return new FindingPresentationModel("repo-" + finding.findingKey(), finding.rule(), finding.severity(), priority == null ? 6 : priority.getPriority(),
				fileLocation(finding.file(), finding.line()), "File", finding.file(), finding.line(), finding.message(), null, null, null, true).feedback(finding.findingKey());
	}
	public com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails getProviderDetails() { return providerDetails; }
	public static FindingPresentationModel fromProvider(String key, com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails details) {
		var location = details.locations().isEmpty() ? null : details.locations().getFirst();
		var priority = details.legacyPriority();
		String title = ProviderFindingTitles.plain(details.title(), details.riskType());
		var model = new FindingPresentationModel("aws-" + key, title, details.severity(), priority == null ? 6 : priority.getPriority(),
				location == null ? "Location unavailable" : fileLocation(location.file(), location.startLine()), "File",
				location == null ? null : location.file(), location == null ? null : location.startLine(),
				providerGuidance(title), details.providerUrl(), null, null, false).feedback(key);
		model.providerDetails = details;
		return model.producedBy("AwsSecurityAgent", null);
	}

	/** What an AWS finding means, in plain words; AWS's own write-up is fetched live in the detail pane. */
	static String providerGuidance(String title) {
		String risk = "AWS security finding".equals(title) ? "security"
				: title.length() > 1 && !Character.isUpperCase(title.charAt(1))
				? Character.toLowerCase(title.charAt(0)) + title.substring(1) : title;
		return "AWS Security Agent reports a possible " + risk + " risk at this location. Review the code at each location below.";
	}

	/** "aws" for an AWS Security Agent finding, "other" for every local scanner's: the report's Scanner filter. */
	public String getScannerGroup() { return providerDetails != null ? "aws" : "other"; }

	private final String id;
	private final String title;
	private final String severity;
	private final int severityValue;
	private final String location;
	private final String locationType;
	private final String fileName;
	private final Integer lineNumber;
	private final String guidance;
	private final String originalGuidance;
	private final String externalUrl;
	private final String score;
	private final String vector;
	private final boolean sourceActionAvailable;
	private final FindingVerification verification;
	private final FindingAction action;
 private String feedbackKey;
 public String getFeedbackKey(){return feedbackKey;}
 private FindingPresentationModel feedback(String key){feedbackKey=key;return this;}
	private ScannerIdentity scanner;
	private Long ruleId;
	private com.tracelink.appsec.watchtower.core.rule.RuleChange ruleChange;

	/** Notes that the rule behind this finding was edited or deleted after the scan, for the "Rule changed" chip. */
	private FindingPresentationModel afterRuleChange(com.tracelink.appsec.watchtower.core.rule.RuleChange change) {
		ruleChange = change;
		return this;
	}

	/** @return the chip text when the rule changed or was deleted after the scan, otherwise null */
	public String getRuleChangeLabel() { return ruleChange == null ? null : ruleChange.label(); }
	/** @return the hover text of that chip, otherwise null */
	public String getRuleChangeTip() { return ruleChange == null ? null : ruleChange.tip(); }

	private FindingPresentationModel producedBy(String module, Long rule) {
		scanner = module == null || module.isBlank() ? null : ScannerIdentity.of(module);
		ruleId = rule;
		return this;
	}

	/** The scanner that found it (name and icon), or null for older scans that did not record it. */
	public ScannerIdentity getScanner() { return scanner; }
	public Long getRuleId() { return ruleId; }
	/** "ImageSecurityReport.java:14" for the list; the full path stays in {@link #getLocation()}. */
	public String getShortLocation() {
		int slash = location.lastIndexOf('/');
		return slash >= 0 && slash < location.length() - 1 ? location.substring(slash + 1) : location;
	}

	private FindingPresentationModel(String id, String title, String severity, int severityValue,
			String location, String locationType, String fileName, Integer lineNumber,
			String guidance, String externalUrl, String score, String vector,
			boolean sourceActionAvailable) {
		this(id, title, severity, severityValue, location, locationType, fileName, lineNumber,
				guidance, externalUrl, score, vector, sourceActionAvailable, null, null);
	}

	private FindingPresentationModel(String id, String title, String severity, int severityValue,
			String location, String locationType, String fileName, Integer lineNumber,
			String guidance, String externalUrl, String score, String vector,
			boolean sourceActionAvailable, FindingVerification verification,
			FindingAction action) {
		this.action = action;
		this.id = id;
		this.title = valueOrFallback(title, "Unnamed finding");
		this.severity = valueOrFallback(severity, "Unknown");
		this.severityValue = severityValue >= 1 && severityValue <= 6 ? severityValue : 6;
		this.location = valueOrFallback(location, "No location");
		this.locationType = locationType;
		this.fileName = fileName;
		this.lineNumber = lineNumber;
		this.originalGuidance = valueOrFallback(guidance, "No guidance is available for this finding.");
        this.guidance = readableGuidance(this.title, this.originalGuidance);
		this.externalUrl = safeExternalUrl(externalUrl);
		this.score = score;
		this.vector = vector;
		this.sourceActionAvailable = sourceActionAvailable;
		this.verification = verification;
	}

	public static List<FindingPresentationModel> fromPullRequest(
			List<PRScanResultViolation> violations) {
		return fromPullRequest(violations, violation -> null);
	}

	/**
	 * @param violations    the scan's violations
	 * @param verifications the "Verify live" state of a violation, or null where none applies
	 * @return the findings
	 */
	public static List<FindingPresentationModel> fromPullRequest(
			List<PRScanResultViolation> violations,
			Function<PRScanResultViolation, FindingVerification> verifications) {
		return fromPullRequest(violations, verifications, violation -> null);
	}

	/**
	 * @param violations    the scan's violations
	 * @param verifications the "Verify live" state of a violation, or null where none applies
	 * @param actions       a module's action on a violation, or null where none applies
	 * @return the findings
	 */
	public static List<FindingPresentationModel> fromPullRequest(
			List<PRScanResultViolation> violations,
			Function<PRScanResultViolation, FindingVerification> verifications,
			Function<PRScanResultViolation, FindingAction> actions) {
		return indexed(violations, (violation, index) -> new FindingPresentationModel(
				"pr-finding-" + index, violation.getViolationName(), violation.getSeverity(),
				violation.getSeverityValue(), fileLocation(violation.getFileName(),
						violation.getLineNumber()), "File", violation.getFileName(),
				violation.getLineNumber(), violation.getMessage(), violation.getExternalUrl(),
				null, null, true, verifications.apply(violation), actions.apply(violation)).feedback(Long.toString(violation.getViolationId()))
				.producedBy(violation.getScannerModule(), violation.getRuleId())
				.afterRuleChange(violation.getRuleChange()));
	}

	public static List<FindingPresentationModel> fromUpload(
			List<UploadScanResultViolation> violations) {
		return indexed(violations, (violation, index) -> new FindingPresentationModel(
				"upload-finding-" + index, violation.getViolationName(), violation.getSeverity(),
				violation.getSeverityValue(), fileLocation(violation.getFileName(),
						violation.getLineNumber()), "File", violation.getFileName(),
				violation.getLineNumber(), violation.getMessage(), violation.getExternalUrl(),
				null, null, false).feedback(Long.toString(violation.getViolationId()))
				.afterRuleChange(violation.getRuleChange()));
	}

	public static List<FindingPresentationModel> fromImage(
			List<ImageScanResultViolation> violations) {
		return indexed(violations, (violation, index) -> new FindingPresentationModel(
				"image-finding-" + index, advisoryTitle(violation.getViolationName(), violation.getPackageName()), violation.getSeverity(),
				violation.getSeverityValue(), valueOrFallback(violation.getPackageName(),
						"Unknown package"), "Package", null, null, violation.getDescription(),
				violation.getUri(), violation.getScore(), violation.getVector(), false));
	}

	private static final java.util.regex.Pattern ADVISORY_WITH_PACKAGE =
			java.util.regex.Pattern.compile("^(\\S+-\\d[\\w.:-]*)\\s+-\\s+\\S.*$");

	/**
	 * Registry titles repeat the package ("CVE-2012-0881 - xerces:xercesImpl"); the package is shown
	 * once under the title, so the list and detail use the advisory ID alone.
	 */
	static String advisoryTitle(String name, String packageName) {
		if (name == null || packageName == null || packageName.isBlank()) {
			return name;
		}
		java.util.regex.Matcher matcher = ADVISORY_WITH_PACKAGE.matcher(name.trim());
		return matcher.matches() ? matcher.group(1) : name;
	}

	private static <T> List<FindingPresentationModel> indexed(List<T> source,
			IndexedMapper<T> mapper) {
		if (source == null || source.isEmpty()) {
			return List.of();
		}
		return IntStream.range(0, source.size())
				.mapToObj(index -> mapper.map(source.get(index), index))
				.filter(Objects::nonNull)
				.toList();
	}

	private static final java.util.regex.Pattern PLACEHOLDER = java.util.regex.Pattern.compile("'{0,2}\\{[0-9]+\\}'{0,2}");
	private static final java.util.regex.Pattern LEADING_NAMED = java.util.regex.Pattern.compile("^(\\w+)\\s+'{0,2}\\{[0-9]+\\}'{0,2}");

	/**
	 * Engine messages are MessageFormat templates; some historical findings kept them unexpanded
	 * ("Parameter ''{0}'' is not assigned..."). People get a readable sentence instead ("This
	 * parameter is not assigned..."); the original stays available as the engine message (UAT #10).
	 */
	static String readableGuidance(String title, String message) {
		if (!PLACEHOLDER.matcher(message).find()) {
			return message;
		}
		if ("ImmutableField".equals(title)) {
			return "Review whether this field can be declared final. The historical message did not identify the field.";
		}
		if ("UnusedPrivateField".equals(title)) {
			return "Review whether this private field is unused. The historical message did not identify the field.";
		}
		java.util.regex.Matcher named = LEADING_NAMED.matcher(message);
		String readable = named.find()
				? "This " + named.group(1).toLowerCase(java.util.Locale.ROOT) + message.substring(named.end())
				: message;
		return PLACEHOLDER.matcher(readable).replaceAll("it").replaceAll("\\s{2,}", " ").trim();
	}

	private static String fileLocation(String fileName, int lineNumber) {
		return valueOrFallback(fileName, "Unknown file") + (lineNumber > 0 ? ":" + lineNumber : "");
	}

	private static String valueOrFallback(String value, String fallback) {
		return value == null || value.isBlank() ? fallback : value;
	}

	private static String safeExternalUrl(String value) {
		if (value == null || value.isBlank()) {
			return null;
		}
		try {
			URI uri = new URI(value);
			String scheme = uri.getScheme();
			return "https".equalsIgnoreCase(scheme) || "http".equalsIgnoreCase(scheme)
					? value : null;
		} catch (URISyntaxException e) {
			return null;
		}
	}

	@FunctionalInterface
	private interface IndexedMapper<T> {
		FindingPresentationModel map(T value, int index);
	}

	public String getId() { return id; }
	public String getTitle() { return title; }
	public String getSeverity() { return severity; }
	public int getSeverityValue() { return severityValue; }
	public String getLocation() { return location; }
	public String getLocationType() { return locationType; }
	public String getFileName() { return fileName; }
	public Integer getLineNumber() { return lineNumber; }
	public String getGuidance() { return guidance; }
    public String getOriginalGuidance() { return originalGuidance; }
    public boolean hasUnresolvedMessage() { return !originalGuidance.equals(guidance); }
	public String getExternalUrl() { return externalUrl; }
	public String getScore() { return score; }
	public String getVector() { return vector; }
	public boolean hasExternalUrl() { return externalUrl != null && !externalUrl.isBlank(); }
	/** "Rule" for Watchtower's rule page, "Advisory" for package findings, else "Documentation". */
	public String getExternalUrlLabel() {
		if (providerDetails != null) return "Open in AWS";
		if (externalUrl != null && externalUrl.contains("/rule/edit/")) return "Rule";
		return "Package".equals(locationType) ? "Advisory" : "Documentation";
	}
	public boolean hasSourceLocation() { return fileName != null && lineNumber != null; }
	public boolean hasSourceAction() { return sourceActionAvailable && hasSourceLocation(); }
	public boolean hasCvss() { return score != null || vector != null; }
	/** CVSS score and vector in plain words for package (image) findings; null for code findings. */
	public CvssText getCvss() { return "Package".equals(locationType) ? CvssText.of(score, vector) : null; }
	public FindingVerification getVerification() { return verification; }
	public boolean hasVerification() { return verification != null; }
	public FindingAction getAction() { return action; }
	public boolean hasAction() { return action != null; }
}
