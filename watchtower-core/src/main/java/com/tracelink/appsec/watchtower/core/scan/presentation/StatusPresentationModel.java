package com.tracelink.appsec.watchtower.core.scan.presentation;

import com.tracelink.appsec.watchtower.core.job.AsyncJobStatus;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;

/** Status label plus redundant icon/text presentation for scan-oriented views. */
public final class StatusPresentationModel {
	/** Hover text for a finished scan whose scanner coverage was not recorded (UAT #32). */
	static final String FINISHED_UNVERIFIED = "Scan finished. Which scanners ran was not recorded"
			+ " for this scan, so we cannot confirm that every scanner checked the code.";

	private final String label;
	private final String tone;
	private final String icon;
	private final String accessibleText;
	private final boolean processingCompleted;

	private StatusPresentationModel(String label, String tone, String icon,
			String accessibleText) {
		this(label, tone, icon, accessibleText, false);
	}

	private StatusPresentationModel(String label, String tone, String icon,
			String accessibleText, boolean processingCompleted) {
		this.label = label;
		this.tone = tone;
		this.icon = icon;
		this.accessibleText = accessibleText;
		this.processingCompleted = processingCompleted;
	}

	public static StatusPresentationModel from(ScanStatus status) {
		if (status == null) {
			return new StatusPresentationModel("Unknown", "neutral", "help",
					"The scan's state was not recorded");
		}
		if (ScanStatus.DONE.equals(status)) {
			return new StatusPresentationModel("Finished", "neutral", "history",
					FINISHED_UNVERIFIED, true);
		}
		if (ScanStatus.FAILED.equals(status)) {
			return new StatusPresentationModel("Failed", "danger", "error",
					"Scan failed");
		}
		if (ScanStatus.IN_PROGRESS.equals(status)) {
			return new StatusPresentationModel("Running", "info", "sync",
					"Scan in progress");
		}
		return new StatusPresentationModel("Queued", "neutral", "schedule",
				"Scan queued");
	}

 public static StatusPresentationModel fromScan(com.tracelink.appsec.watchtower.core.scan.AbstractScanEntity<?,?> scan) { return from(ScanAssessment.from(scan)); }
 public static StatusPresentationModel from(com.tracelink.appsec.watchtower.core.scan.code.scm.repo.entity.RepoScanEntity scan) {
  // A scan that ended without scanning anything is not a finished scan of the code
  var outcome=scan.getOutcome();
  if(ScanStatus.DONE.equals(scan.getStatus())&&outcome!=null) {
   String why=switch(outcome) {
    case BRANCH_MISSING -> "The branch was not found in the repository, so nothing was scanned.";
    case SKIPPED_SIZE -> "The repository is larger than the size limit, so nothing was scanned.";
    case SKIPPED_STALE -> "The repository has had no recent changes, so it was skipped.";
    default -> null;
   };
   if(why!=null)return new StatusPresentationModel("Not scanned","warning","block",why,true);
  }
  return from(ScanAssessment.from(scan));
 }
 /**
  * A finished scan reads as Full scan (every selected scanner ran), Partial scan (a scanner was
  * skipped, failed or unavailable) or Finished (coverage not recorded); the hover text says why.
  */
 public static StatusPresentationModel from(ScanAssessment assessment) {
  if ("COMPLETED".equals(assessment.processing())) {
   String reasons = String.join(" ", assessment.reasons());
   if (assessment.complete()) {
    return new StatusPresentationModel("Full scan", "success", "check_circle",
      "Scan finished and every selected scanner ran.", true);
   }
   if ("INCOMPLETE".equals(assessment.completeness())) {
    return new StatusPresentationModel("Partial scan", "warning", "warning",
      ("Scan finished, but not every scanner ran. " + reasons).trim()
        + " A low finding count may not mean the code is clean.", true);
   }
   return new StatusPresentationModel("Finished", "neutral", "history",
     reasons.isBlank() ? FINISHED_UNVERIFIED : "Scan finished. " + reasons, true);
  }
  return from(switch(assessment.processing()){case "FAILED"->ScanStatus.FAILED;case "RUNNING"->ScanStatus.IN_PROGRESS;case "QUEUED"->ScanStatus.NOT_STARTED;default->(ScanStatus)null;});
 }

	/** Queue jobs describe processing only; they do not establish scan coverage. */
	public static StatusPresentationModel from(AsyncJobStatus status) {
		if (status == null) return from((ScanStatus) null);
		return switch (status) {
			case DONE -> new StatusPresentationModel("Completed", "success", "check_circle", "Job completed");
			case FAILED -> new StatusPresentationModel("Failed", "danger", "error", "Job failed");
			case RUNNING -> new StatusPresentationModel("Running", "info", "sync", "Job in progress");
			case QUEUED -> new StatusPresentationModel("Queued", "neutral", "schedule", "Job queued");
		};
	}

	/** True once processing finished, whatever the scanner coverage; reports exist then. */
	public boolean isProcessingCompleted() {
		return processingCompleted || "Completed".equals(label);
	}

	public String getLabel() { return label; }
	public String getTone() { return tone; }
	public String getIcon() { return icon; }
	public String getAccessibleText() { return accessibleText; }
}
