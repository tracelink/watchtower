package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus.ScanStatusConverter;
import com.tracelink.appsec.watchtower.core.scan.repository.RepositoryEntity;

/**
 * One branch of one repository scanned in one run of a plan. Holds only the summary that lists
 * and dashboards need; the findings themselves are an object in the report store, named by
 * {@link #getReportKey()}, and never contain source code.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "repo_scans")
public class RepoScanEntity {
    @Column(name = "provider_summary_json", columnDefinition = "TEXT")
    private String providerSummaryJson;
    public String getProviderSummaryJson() { return providerSummaryJson; }
    public void setProviderSummaryJson(String json) { providerSummaryJson = json; }
    public java.util.List<com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference> getProviderAssessments() {
        return com.tracelink.appsec.watchtower.core.scan.code.report.ProviderAssessmentReference.decode(providerSummaryJson);
    }
    public int getCombinedFindingCount() { return findingCount + getProviderFindingCount(); }
    @jakarta.persistence.Transient
    public com.tracelink.appsec.watchtower.core.scan.presentation.ScanFindingSummary getFindingSummary() {
        return com.tracelink.appsec.watchtower.core.scan.presentation.ScanFindingSummary.of(
                getSeverityCounts(), findingCount, getProviderAssessments());
    }
    public boolean isProviderComplete() { return getProviderAssessments().stream().allMatch(r -> r.status().complete()); }
    public int getProviderFindingCount() { return getProviderAssessments().stream().mapToInt(r -> r.status().imported()).sum(); }

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "scan_id")
	private long id;

	@Column(name = "plan_id")
	private long planId;

	@Column(name = "run_no")
	private int runNo;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "repo_entity_id")
	private RepositoryEntity repository;

	@Column(name = "branch")
	private String branch;

	@Column(name = "commit_hash")
	private String commitHash;

	@Column(name = "commit_date")
	private Long commitDate;

	@Column(name = "ruleset_name")
	private String rulesetName;

	@Column(name = "ruleset_fingerprint")
	private String rulesetFingerprint;

	@Convert(converter = ScanStatusConverter.class)
	@Column(name = "status")
	private ScanStatus status;

	@Enumerated(EnumType.STRING)
	@Column(name = "outcome")
	private RepoScanOutcome outcome;

	@Column(name = "priority")
	private int priority;

	@Column(name = "submit_date")
	private long submitDate;

	@Column(name = "start_date")
	private Long startDate;

	@Column(name = "end_date")
	private Long endDate;

	@Column(name = "attempts")
	private int attempts;

	@Column(name = "worker_id")
	private String workerId;

	@Column(name = "heartbeat_at")
	private Long heartbeatAt;

	@Column(name = "error")
	private String error;

	@Column(name = "finding_count")
	private int findingCount;

	@Column(name = "max_severity")
	private Integer maxSeverity;

	@Column(name = "severity_counts")
	private String severityCounts;

	/** JSON object of rule name to finding count. */
	@Column(name = "rule_counts")
	private String ruleCounts;

	@Column(name = "new_count")
	private Integer newCount;

	@Column(name = "fixed_count")
	private Integer fixedCount;

	@Column(name = "report_key")
	private String reportKey;

	@Column(name = "rules_evaluated")
	private Integer rulesEvaluated;

	@Column(name = "scanner_executions_json")
	private String scannerExecutionsJson;

	@Column(name = "execution_snapshot_json", columnDefinition = "LONGTEXT")
	private String executionSnapshotJson;

	public String getExecutionSnapshotJson() { return executionSnapshotJson; }
	public void setExecutionSnapshotJson(String json) { executionSnapshotJson = json; }

    public com.tracelink.appsec.watchtower.core.scan.presentation.ScanAssessment getAssessment() { return com.tracelink.appsec.watchtower.core.scan.presentation.ScanAssessment.from(this); }

	public long getId() {
		return id;
	}

	public long getPlanId() {
		return planId;
	}

	public void setPlanId(long planId) {
		this.planId = planId;
	}

	public int getRunNo() {
		return runNo;
	}

	public void setRunNo(int runNo) {
		this.runNo = runNo;
	}

	public RepositoryEntity getRepository() {
		return repository;
	}

	public void setRepository(RepositoryEntity repository) {
		this.repository = repository;
	}

	public String getBranch() {
		return branch;
	}

	public void setBranch(String branch) {
		this.branch = branch;
	}

	public String getCommitHash() {
		return commitHash;
	}

	public void setCommitHash(String commitHash) {
		this.commitHash = commitHash;
	}

	public long getCommitDate() {
		return commitDate == null ? 0 : commitDate;
	}

	public void setCommitDate(long commitDate) {
		this.commitDate = commitDate;
	}

	public String getRulesetName() {
		return rulesetName;
	}

	public void setRulesetName(String rulesetName) {
		this.rulesetName = rulesetName;
	}

	public String getRulesetFingerprint() {
		return rulesetFingerprint;
	}

	public void setRulesetFingerprint(String rulesetFingerprint) {
		this.rulesetFingerprint = rulesetFingerprint;
	}

	public ScanStatus getStatus() {
		return status;
	}

	public void setStatus(ScanStatus status) {
		this.status = status;
	}

	public RepoScanOutcome getOutcome() {
		return outcome;
	}

	public void setOutcome(RepoScanOutcome outcome) {
		this.outcome = outcome;
	}

	public int getPriority() {
		return priority;
	}

	public void setPriority(int priority) {
		this.priority = priority;
	}

	public long getSubmitDate() {
		return submitDate;
	}

	public void setSubmitDate(long submitDate) {
		this.submitDate = submitDate;
	}

	public long getStartDate() {
		return startDate == null ? 0 : startDate;
	}

	public void setStartDate(long startDate) {
		this.startDate = startDate;
	}

	public long getEndDate() {
		return endDate == null ? 0 : endDate;
	}

	public void setEndDate(long endDate) {
		this.endDate = endDate;
	}

	public int getAttempts() {
		return attempts;
	}

	public void setAttempts(int attempts) {
		this.attempts = attempts;
	}

	public String getWorkerId() {
		return workerId;
	}

	public long getHeartbeatAt() {
		return heartbeatAt == null ? 0 : heartbeatAt;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	public int getFindingCount() {
		return findingCount;
	}

	/**
	 * @return the highest severity found, or null if nothing was found
	 */
	public RulePriority getMaxSeverity() {
		return maxSeverity == null ? null : RulePriority.valueOf(maxSeverity.intValue());
	}

	public SeverityCounts getSeverityCounts() {
		return SeverityCounts.parse(severityCounts);
	}

	/**
	 * Sets the finding total, highest severity and per-severity counts together, so they always
	 * agree.
	 *
	 * @param counts the counts per severity
	 */
	public void setSeverityCounts(SeverityCounts counts) {
		this.severityCounts = counts.format();
		this.findingCount = counts.total();
		RulePriority highest = counts.highest();
		this.maxSeverity = highest == null ? null : highest.getPriority();
	}

	public String getRuleCounts() {
		return ruleCounts;
	}

	public void setRuleCounts(String ruleCounts) {
		this.ruleCounts = ruleCounts;
	}

	public Integer getNewCount() {
		return newCount;
	}

	public void setNewCount(Integer newCount) {
		this.newCount = newCount;
	}

	public Integer getFixedCount() {
		return fixedCount;
	}

	public void setFixedCount(Integer fixedCount) {
		this.fixedCount = fixedCount;
	}

	public String getReportKey() {
		return reportKey;
	}

	public void setReportKey(String reportKey) {
		this.reportKey = reportKey;
	}

	public Integer getRulesEvaluated() {
		return rulesEvaluated;
	}

	public void setRulesEvaluated(Integer rulesEvaluated) {
		this.rulesEvaluated = rulesEvaluated;
	}

	/** This scan's scanner tiles (local executions and remote providers), for its report and run rows. */
	@jakarta.persistence.Transient
	public com.tracelink.appsec.watchtower.core.scan.presentation.ScannerBadge.Summary getScannerTiles() {
		return com.tracelink.appsec.watchtower.core.scan.presentation.ScannerBadge.from(scannerExecutionsJson,
				providerSummaryJson);
	}

	public String getScannerExecutionsJson() {
		return scannerExecutionsJson;
	}

	public void setScannerExecutionsJson(String scannerExecutionsJson) {
		this.scannerExecutionsJson = scannerExecutionsJson;
	}
}
