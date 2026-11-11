package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.util.List;
import java.util.UUID;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot;

/**
 * The full result of one repository scan, as stored in the report store. Holds where each
 * finding is and what rule it broke, never the code itself: a finding's fingerprint is a one-way
 * hash, and code is shown only by fetching it live from the SCM when a report is viewed.
 *
 * @param schema        the report format version
 * @param scanId        the scan
 * @param apiLabel      the integration
 * @param repository    the repository name
 * @param branch        the branch scanned
 * @param commitHash    the commit scanned
 * @param rulesetName   the ruleset used
 * @param findings      what was found, at most the configured cap
 * @param fixed         findings of the previous scan of the branch that are gone
 * @param scannerErrors scanner problems worth showing (no code)
 * @param totalFindings the number of findings before any cap
 * @author Watchtower
 */
public record RepoScanReport(int schema, long scanId, String apiLabel, String repository,
		String branch, String commitHash, String rulesetName, List<Finding> findings,
		List<Fixed> fixed, List<String> scannerErrors, int totalFindings,
		CodeScanExecutionSnapshot executionSnapshot,
  List<com.tracelink.appsec.watchtower.core.metrics.RuleMetricWriter.Totals> identityCounts, List<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference> providerAssessments,
        String scope, ScanComparison comparison) {

	public static final int SCHEMA = 5;
    public static final String REPOSITORY_SCOPE = "repository-full-source-v1";

 public RepoScanReport(int schema,long scanId,String apiLabel,String repository,String branch,String commitHash,String rulesetName,List<Finding> findings,List<Fixed> fixed,List<String> scannerErrors,int totalFindings,CodeScanExecutionSnapshot snapshot,List<com.tracelink.appsec.watchtower.core.metrics.RuleMetricWriter.Totals> identityCounts,List<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference> providers){
  this(schema,scanId,apiLabel,repository,branch,commitHash,rulesetName,findings,fixed,scannerErrors,totalFindings,snapshot,identityCounts,providers,null,null);
 }
 public RepoScanReport withComparison(String scope,ScanComparison comparison) {
  return new RepoScanReport(schema,scanId,apiLabel,repository,branch,commitHash,rulesetName,findings,fixed,scannerErrors,totalFindings,executionSnapshot,identityCounts,providerAssessments,scope,comparison);
 }
 /** Corrected presentation only. Original artifacts remain untouched in the report store. */
 public RepoScanReport interpreted() {
  var interpretation=comparison==null?ScanComparison.unavailable(null,"HISTORICAL_DELTA_UNVERIFIED: baseline identity and compatible coverage were not recorded"):comparison;
  return new RepoScanReport(schema,scanId,apiLabel,repository,branch,commitHash,rulesetName,
    interpretation.comparable()?findings:findings.stream().map(f->f.withNew(false)).toList(),
    interpretation.comparable()?fixed:List.of(),scannerErrors,totalFindings,executionSnapshot,identityCounts,providerAssessments,scope,interpretation);
 }
 public RepoScanReport(int schema,long scanId,String apiLabel,String repository,String branch,String commitHash,String rulesetName,List<Finding> findings,List<Fixed> fixed,List<String> scannerErrors,int totalFindings,CodeScanExecutionSnapshot snapshot,List<com.tracelink.appsec.watchtower.core.metrics.RuleMetricWriter.Totals> identityCounts){
  this(schema,scanId,apiLabel,repository,branch,commitHash,rulesetName,findings,fixed,scannerErrors,totalFindings,snapshot,identityCounts,List.of());
 }
 public RepoScanReport(int schema,long scanId,String apiLabel,String repository,String branch,String commitHash,String rulesetName,List<Finding> findings,List<Fixed> fixed,List<String> scannerErrors,int totalFindings,CodeScanExecutionSnapshot snapshot){
  this(schema,scanId,apiLabel,repository,branch,commitHash,rulesetName,findings,fixed,scannerErrors,totalFindings,snapshot,null);
 }

	public RepoScanReport(int schema, long scanId, String apiLabel, String repository,
			String branch, String commitHash, String rulesetName, List<Finding> findings,
			List<Fixed> fixed, List<String> scannerErrors, int totalFindings) {
		this(schema, scanId, apiLabel, repository, branch, commitHash, rulesetName, findings,
				fixed, scannerErrors, totalFindings, null);
	}

	public RepoScanReport {
        providerAssessments = providerAssessments == null ? List.of() : List.copyOf(providerAssessments);
		findings = findings == null ? List.of() : List.copyOf(findings);
		fixed = fixed == null ? List.of() : List.copyOf(fixed);
		scannerErrors = scannerErrors == null ? List.of() : List.copyOf(scannerErrors);
	}

	/**
	 * @return true if more findings were found than the report holds
	 */
	public boolean isTruncated() {
		return totalFindings > findings.size();
	}

    /** Native provider totals are additive; six legacy buckets and local deltas retain their meaning. */
    public int combinedTotalFindings() { return totalFindings + providerAssessments.stream().mapToInt(r -> r.status().imported()).sum(); }
    public boolean providerComplete() { return providerAssessments.stream().allMatch(r -> r.status().complete()); }

	/** An occurrence identifier, independent of the cross-scan change fingerprint. */
	public static String createFindingKey(long scanId, int ordinal) {
		return RuleRevision.definition("repository-finding-occurrence", "v1")
				.field("scanId", Long.toString(scanId)).field("ordinal", Integer.toString(ordinal))
				// A rewritten/retried artifact must never repoint an existing feedback reference.
				.field("nonce", UUID.randomUUID().toString()).hash();
	}

	/**
	 * One finding. No source text.
	 *
	 * @param rule        the rule's name
	 * @param severity    the severity name
	 * @param file        the path relative to the repository root
	 * @param line        the line number, 0 if none
	 * @param message     the rule's message
	 * @param fingerprint identifies the same finding across scans despite line moves
	 * @param isNew       true if the previous scan of the branch did not have it
	 * @param sensitive   true if a secrets scanner found it, so its line is never shown; null
	 *                    in reports written before this was recorded (then the rule decides)
	 */
	public record Finding(String rule, String severity, String file, int line, String message,
			String fingerprint, boolean isNew, Boolean sensitive, RuleExecutionIdentity ruleIdentity,
			String engineFingerprint, Boolean effectiveBlocking, String findingKey) {
		public Finding(String rule, String severity, String file, int line, String message,
				String fingerprint, boolean isNew, Boolean sensitive) {
			this(rule, severity, file, line, message, fingerprint, isNew, sensitive, null, null, null, null);
		}

		public Finding withNew(boolean value) {
			return new Finding(rule, severity, file, line, message, fingerprint, value, sensitive,
					ruleIdentity, engineFingerprint, effectiveBlocking, findingKey);
		}

		public Finding reusedIn(long scanId, int ordinal) {
			return new Finding(rule, severity, file, line, message, fingerprint, false, sensitive,
					ruleIdentity, engineFingerprint, effectiveBlocking, RepoScanReport.createFindingKey(scanId, ordinal));
		}
	}

	/**
	 * A finding of the previous scan that this scan no longer has.
	 *
	 * @param rule    the rule's name
	 * @param file    the path
	 * @param message the rule's message
	 */
	public record Fixed(String rule, String file, String message, RuleExecutionIdentity ruleIdentity,
			String engineFingerprint) {
		public Fixed(String rule, String file, String message) {
			this(rule, file, message, null, null);
		}
	}
}
