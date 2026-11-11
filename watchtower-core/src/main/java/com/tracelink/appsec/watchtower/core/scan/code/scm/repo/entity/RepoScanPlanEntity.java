package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * What to scan and when: an integration's repositories chosen by a selector, the branches to
 * scan, the ruleset, and how often. Each time a plan fires is a run; its scans share the
 * plan id and run number. An ad-hoc scan is a plan with frequency {@link PlanFrequency#ONCE}.
 *
 * @author Watchtower
 */
@Entity
@Table(name = "repo_scan_plans")
public class RepoScanPlanEntity {

	/** How one-off scans were named by default before they were named after their target. */
	private static final String OLD_DEFAULT_NAME = "Scan by ";

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "plan_id")
	private long id;

	@Column(name = "name")
	private String name;

	@Column(name = "api_label")
	private String apiLabel;

	/** One selector per line; see RepoSelector. */
	@Column(name = "repo_selector")
	private String repoSelector;

	/** Blank for each repository's default branch; else comma separated names or globs. */
	@Column(name = "branch_selector")
	private String branchSelector;

	/** Null to use each repository's own ruleset. */
	@Column(name = "ruleset_id")
	private Long rulesetId;

	@Enumerated(EnumType.STRING)
	@Column(name = "frequency")
	private PlanFrequency frequency;

	@Column(name = "schedule_hour")
	private Integer scheduleHour;

	@Column(name = "schedule_day")
	private Integer scheduleDay;

	@Column(name = "skip_stale_days")
	private Integer skipStaleDays;

	@Column(name = "next_run_at")
	private Long nextRunAt;

	@Column(name = "last_run_at")
	private Long lastRunAt;

	@Column(name = "run_count")
	private int runCount;

	@Column(name = "enabled")
	private boolean enabled = true;

	@Column(name = "created_by")
	private String createdBy;

	@Column(name = "created_at")
	private long createdAt;

	public long getId() {
		return id;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getApiLabel() {
		return apiLabel;
	}

	public void setApiLabel(String apiLabel) {
		this.apiLabel = apiLabel;
	}

	public String getRepoSelector() {
		return repoSelector;
	}

	public void setRepoSelector(String repoSelector) {
		this.repoSelector = repoSelector;
	}

	public String getBranchSelector() {
		return branchSelector;
	}

	public void setBranchSelector(String branchSelector) {
		this.branchSelector = branchSelector;
	}

	public Long getRulesetId() {
		return rulesetId;
	}

	public void setRulesetId(Long rulesetId) {
		this.rulesetId = rulesetId;
	}

	public PlanFrequency getFrequency() {
		return frequency;
	}

	public void setFrequency(PlanFrequency frequency) {
		this.frequency = frequency;
	}

	public Integer getScheduleHour() {
		return scheduleHour;
	}

	public void setScheduleHour(Integer scheduleHour) {
		this.scheduleHour = scheduleHour;
	}

	public Integer getScheduleDay() {
		return scheduleDay;
	}

	public void setScheduleDay(Integer scheduleDay) {
		this.scheduleDay = scheduleDay;
	}

	public Integer getSkipStaleDays() {
		return skipStaleDays;
	}

	public void setSkipStaleDays(Integer skipStaleDays) {
		this.skipStaleDays = skipStaleDays;
	}

	public Long getNextRunAt() {
		return nextRunAt;
	}

	public void setNextRunAt(Long nextRunAt) {
		this.nextRunAt = nextRunAt;
	}

	public Long getLastRunAt() {
		return lastRunAt;
	}

	public void setLastRunAt(Long lastRunAt) {
		this.lastRunAt = lastRunAt;
	}

	public int getRunCount() {
		return runCount;
	}

	/**
	 * How a run of this plan is named on every page. A one-off scan is its plan's only run, so
	 * it is numbered by the plan ("Scan #57 · payments-api"; plan ids rise across all scans);
	 * a recurring plan's run by its run number ("Nightly sweep · run 4").
	 *
	 * @param runNo the run
	 * @return its label
	 */
	/**
	 * The plan's name for lists: its own name, or what it scans when it still has the old
	 * automatic "Scan by &lt;user&gt;" name (so rows no longer mix "Scan #4 by …" and "Scan #6 · …").
	 */
	public String getDisplayName() {
		if (name != null && name.startsWith(OLD_DEFAULT_NAME)) {
			return repoSelector == null || repoSelector.isBlank() ? "Scan #" + id : repoSelector;
		}
		return name == null || name.isBlank() ? "Scan #" + id : name;
	}

	public String runLabel(int runNo) {
		if (frequency != null && frequency.isRecurring()) {
			return name + " · run " + runNo;
		}
		return name != null && name.startsWith(OLD_DEFAULT_NAME)
				? "Scan #" + id + " by " + name.substring(OLD_DEFAULT_NAME.length())
				: "Scan #" + id + " · " + name;
	}

	public void setRunCount(int runCount) {
		this.runCount = runCount;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public String getCreatedBy() {
		return createdBy;
	}

	public void setCreatedBy(String createdBy) {
		this.createdBy = createdBy;
	}

	public long getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(long createdAt) {
		this.createdAt = createdAt;
	}
}
