package com.tracelink.appsec.watchtower.core.scan.queue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.scan.queue.PRScanWorkItemEntity.WorkStatus;

/** Maintains the durable, non-terminal PR scan workload shown on dashboards. */
@Service
public class PRScanWorkloadService {
	private final PRScanWorkItemRepository repository;

	public PRScanWorkloadService(PRScanWorkItemRepository repository) {
		this.repository = repository;
	}

	@Transactional
	public void queued(ScanRequestMessage message) {
		long now = System.currentTimeMillis();
		PRScanWorkItemEntity item = repository.findByDedupKey(key(message))
				.orElseGet(PRScanWorkItemEntity::new);
		item.setDedupKey(key(message));
		item.setApiLabel(message.apiLabel());
		item.setRepoName(message.repoName());
		item.setPrId(message.prId());
		item.setCommitHash(message.commitHash());
		item.setStatus(WorkStatus.QUEUED);
		item.setEnqueuedAt(message.enqueuedAt());
		item.setStartedAt(null);
		item.setUpdatedAt(now);
		item.setFailureReason(null);
		repository.save(item);
	}

	@Transactional
	public void validationFailed(ScanRequestMessage message, String reason) {
		PRScanWorkItemEntity item = repository.findByDedupKey(key(message))
				.orElseGet(PRScanWorkItemEntity::new);
		item.setDedupKey(key(message));
		item.setApiLabel(message.apiLabel());
		item.setRepoName(message.repoName());
		item.setPrId(message.prId());
		item.setCommitHash(message.commitHash());
		item.setStatus(WorkStatus.VALIDATION_FAILED);
		item.setEnqueuedAt(message.enqueuedAt());
		item.setStartedAt(null);
		item.setFailureReason(reason);
		item.setUpdatedAt(System.currentTimeMillis());
		repository.save(item);
	}

	@Transactional
	public void running(ScanRequestMessage message) {
		PRScanWorkItemEntity item = repository.findByDedupKey(key(message)).orElse(null);
		if (item == null) {
			queued(message);
			item = repository.findByDedupKey(key(message)).orElseThrow();
		}
		long now = System.currentTimeMillis();
		item.setStatus(WorkStatus.RUNNING);
		item.setStartedAt(now);
		item.setUpdatedAt(now);
		item.setFailureReason(null);
		repository.save(item);
	}

	@Transactional
	public void completed(ScanRequestMessage message) {
		repository.deleteByDedupKey(key(message));
	}

	/**
	 * @return whether a scan of the pull request, of any commit, is queued or running
	 */
	@Transactional(readOnly = true)
	public boolean hasPendingScan(String apiLabel, String repoName, String prId) {
		return repository.existsByApiLabelAndRepoNameAndPrIdAndStatusIn(apiLabel, repoName, prId,
				List.of(WorkStatus.QUEUED, WorkStatus.RUNNING));
	}

	/**
	 * Removes a request that failed validation from the list. Only failed requests may go: a queued
	 * or running one still stands for real work.
	 *
	 * @throws IllegalArgumentException if the request is gone or is not a failed one
	 */
	@Transactional
	public void dismissFailed(long id) {
		PRScanWorkItemEntity item = repository.findById(id).orElseThrow(
				() -> new IllegalArgumentException("That request is no longer in the list"));
		if (item.getStatus() != WorkStatus.VALIDATION_FAILED) {
			throw new IllegalArgumentException(
					"Only a request that failed validation can be removed");
		}
		repository.delete(item);
	}

	/** A request that has waited this long without starting was dropped, whatever the queue says. */
	static final Duration STALLED_AFTER = Duration.ofHours(24);

	@Transactional
	public PRScanWorkloadModel getWorkload() {
		long now = System.currentTimeMillis();
		expireStalled(now);
		long recentFailureCutoff = now - Duration.ofHours(24).toMillis();
		List<PRScanWorkItemEntity> entities = new ArrayList<>(
				repository.findAllByStatusInOrderByEnqueuedAtAsc(
						List.of(WorkStatus.QUEUED, WorkStatus.RUNNING)));
		entities.addAll(repository
				.findAllByStatusAndUpdatedAtGreaterThanEqualOrderByEnqueuedAtAsc(
						WorkStatus.VALIDATION_FAILED, recentFailureCutoff));
		entities.sort(Comparator.comparingLong(PRScanWorkItemEntity::getEnqueuedAt));
		long oldestQueued = entities.stream()
				.filter(item -> item.getStatus() == WorkStatus.QUEUED)
				.mapToLong(PRScanWorkItemEntity::getEnqueuedAt).min().orElse(now);
		return new PRScanWorkloadModel(repository.countByStatus(WorkStatus.QUEUED),
				repository.countByStatus(WorkStatus.RUNNING),
				repository.countByStatusAndUpdatedAtGreaterThanEqual(
						WorkStatus.VALIDATION_FAILED, recentFailureCutoff),
				formatAge(Math.max(0, now - oldestQueued)),
				entities.stream().map(item -> PRScanWorkloadModel.Item.from(item, now)).toList());
	}

	/**
	 * Moves requests queued for over a day to failed, so the waiting count and the oldest wait show
	 * real work. A request whose pull request was refused or removed never left "queued" and showed
	 * as waiting for days; if one does start later it is set running again.
	 */
	private void expireStalled(long now) {
		List<PRScanWorkItemEntity> stalled = repository.findAllByStatusAndEnqueuedAtLessThan(
				WorkStatus.QUEUED, now - STALLED_AFTER.toMillis());
		for (PRScanWorkItemEntity item : stalled) {
			item.setStatus(WorkStatus.VALIDATION_FAILED);
			item.setFailureReason("Waited more than a day without starting; the request was dropped.");
			item.setUpdatedAt(now);
		}
		if (!stalled.isEmpty()) {
			repository.saveAll(stalled);
		}
	}

	static String key(ScanRequestMessage message) {
		String source = message.apiLabel() + "/" + message.repoName() + "/" + message.prId()
				+ "/" + message.commitHash();
		try {
			return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
					.digest(source.getBytes(StandardCharsets.UTF_8)));
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("SHA-256 is unavailable", e);
		}
	}

	static String formatAge(long millis) {
		long seconds = millis / 1000;
		if (seconds < 60) return seconds + "s";
		long minutes = seconds / 60;
		if (minutes < 60) return minutes + "m";
		long hours = minutes / 60;
		return hours < 24 ? hours + "h " + minutes % 60 + "m" : hours / 24 + "d "
				+ hours % 24 + "h";
	}
}
