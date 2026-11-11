package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.tracelink.appsec.watchtower.core.queue.SqsQueueClient;

/**
 * Chooses where repository scan work goes: the SQS FIFO queue when one is configured, otherwise
 * this process. With more than one pod an in-process queue would run work twice and lose it on
 * restart, so a multi-pod deployment without a queue refuses to start.
 *
 * @author Watchtower
 */
@Configuration
public class RepoQueueConfiguration {

	private static final Logger LOG = LoggerFactory.getLogger(RepoQueueConfiguration.class);

	@Bean
	public SqsQueueClient repoScanQueueClient(
			@Value("${watchtower.reposcan.queue-url:}") String queueUrl,
			@Value("${watchtower.reposcan.queue-region:us-east-1}") String region) {
		return new SqsQueueClient(queueUrl, region);
	}

	@Bean
	public RepoWorkQueue repoWorkQueue(SqsQueueClient repoScanQueueClient,
			ObjectProvider<RepoWorkProcessor> processor,
			@Value("${watchtower.cluster.multi-pod:false}") boolean multiPod) {
		if (repoScanQueueClient.isEnabled()) {
			LOG.info("Repository scan work goes to the SQS queue");
			return new SqsRepoWorkQueue(repoScanQueueClient);
		}
		if (multiPod) {
			throw new IllegalStateException("watchtower.cluster.multi-pod is set but"
					+ " watchtower.reposcan.queue-url is not: repository scans need the shared"
					+ " queue when more than one pod runs");
		}
		LOG.info("No repository scan queue configured; running repository scan work in this"
				+ " process");
		return new LocalRepoWorkQueue(processor);
	}
}
