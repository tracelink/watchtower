package com.tracelink.appsec.watchtower.core.scan.queue;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.List;

import com.tracelink.appsec.watchtower.core.scan.queue.PRScanWorkItemEntity.WorkStatus;

/** Compact live workload model shared by Home and the PR dashboard. */
public record PRScanWorkloadModel(long queued, long running, long validationFailed,
		String oldestWait,
		List<Item> items) {
	public boolean isEmpty() { return items.isEmpty(); }
	public long getQueued() { return queued; }
	public long getRunning() { return running; }
	public long getValidationFailed() { return validationFailed; }
	public String getOldestWait() { return oldestWait; }
	public List<Item> getItems() { return items; }

	/** @param canDismiss true only for a request that failed validation and may be removed */
	public record Item(String target, String apiLabel, String status, String tone,
			String icon, String age, String reason, LocalDateTime enqueuedAt, long id,
			boolean canDismiss) {
		/** For the shared local-time renderer, which shows the viewer's own zone (UAT #9). */
		public long enqueuedMillis() {
			return enqueuedAt.atZone(ZoneId.systemDefault()).toInstant().toEpochMilli();
		}

		static Item from(PRScanWorkItemEntity entity, long now) {
			boolean running = entity.getStatus() == WorkStatus.RUNNING;
			boolean failed = entity.getStatus() == WorkStatus.VALIDATION_FAILED;
			long ageStart = running && entity.getStartedAt() != null
					? entity.getStartedAt() : entity.getEnqueuedAt();
			return new Item(entity.getRepoName() + " #" + entity.getPrId(),
					entity.getApiLabel(), failed ? "Validation failed"
							: running ? "Scanning" : "Queued",
					failed ? "danger" : running ? "info" : "neutral",
					failed ? "error" : running ? "sync" : "schedule",
					PRScanWorkloadService.formatAge(Math.max(0, now - ageStart)),
					entity.getFailureReason(),
					LocalDateTime.ofInstant(Instant.ofEpochMilli(entity.getEnqueuedAt()),
							ZoneId.systemDefault()),
					entity.getId(), failed);
		}
	}
}
