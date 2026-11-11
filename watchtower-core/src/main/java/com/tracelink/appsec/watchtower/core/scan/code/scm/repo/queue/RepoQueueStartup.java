package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.scan.ScanStatus;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.repository.RepoScanRepository;

/**
 * After a restart, re-sends unfinished repository scan work to an in-process queue, whose
 * pending work died with the old process. SQS keeps its own messages, so nothing is re-sent when
 * the shared queue is in use.
 *
 * @author Watchtower
 */
@Component
public class RepoQueueStartup {

	private static final Logger LOG = LoggerFactory.getLogger(RepoQueueStartup.class);

	private final RepoWorkQueue queue;

	private final RepoScanRepository scans;

	private final AsyncJobService jobs;

	private final boolean enabled;

	@Autowired
	public RepoQueueStartup(RepoWorkQueue queue, RepoScanRepository scans, AsyncJobService jobs,
			@Value("${watchtower.runAfterStartup:true}") boolean enabled) {
		this.queue = queue;
		this.scans = scans;
		this.jobs = jobs;
		this.enabled = enabled;
	}

	@EventListener(ApplicationReadyEvent.class)
	public void resendUnfinishedWork() {
		if (!enabled || queue.isDistributed()) {
			return;
		}
		jobs.requeueUnfinished();
		List<Long> unfinished = scans.findIdsByStatusIn(
				List.of(ScanStatus.IN_PROGRESS, ScanStatus.NOT_STARTED));
		unfinished.forEach(queue::sendScan);
		if (!unfinished.isEmpty()) {
			LOG.info("Re-queued {} unfinished repository scans after restart", unfinished.size());
		}
	}
}
