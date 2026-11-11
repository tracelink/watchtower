package com.tracelink.appsec.module.awssecurity;

import java.util.concurrent.*;
import org.springframework.stereotype.Component;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.data.domain.PageRequest;
import jakarta.annotation.PreDestroy;
import com.tracelink.appsec.watchtower.core.queue.SqsQueueClient;

/** Dedicated provider queue: local PR receipts and consumer threads never wait for AWS. */
@Component
public class AwsSecurityQueue {
    private final SqsQueueClient queue;
    private final software.amazon.awssdk.services.sqs.SqsClient client;
    private final AwsSecurityRunRepository runs;
    private final AwsSecurityPersistence persistence;
    private final AwsSecurityScanCoordinator coordinator;
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> { var t = new Thread(r, "aws-security-worker"); t.setDaemon(true); return t; });
    private final Semaphore slot = new Semaphore(1);
    public AwsSecurityQueue(AwsSecuritySettings settings, AwsSecurityRunRepository runs,
            AwsSecurityPersistence persistence, AwsSecurityScanCoordinator coordinator) {
        this.client = settings.queueUrl().isBlank() ? null : software.amazon.awssdk.services.sqs.SqsClient.builder()
            .region(software.amazon.awssdk.regions.Region.of(settings.region().isBlank() ? "us-east-1" : settings.region()))
            .credentialsProvider(software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider.create())
            .httpClientBuilder(software.amazon.awssdk.http.apache.ApacheHttpClient.builder()
                .connectionTimeout(java.time.Duration.ofSeconds(5)).connectionAcquisitionTimeout(java.time.Duration.ofSeconds(5))
                .socketTimeout(java.time.Duration.ofSeconds(30)).maxConnections(8))
            .overrideConfiguration(c -> c.apiCallTimeout(java.time.Duration.ofSeconds(60)).apiCallAttemptTimeout(java.time.Duration.ofSeconds(35)))
            .build();
        this.queue = new SqsQueueClient(settings.queueUrl(), client);
        this.runs=runs; this.persistence=persistence; this.coordinator=coordinator;
    }
    /** Repair DB/send gaps and lost workers, including while new submissions are disabled. */
    @Scheduled(fixedDelayString = "${watchtower.aws-security.reconcile-ms:10000}")
    public void reconcile() {
        if (!queue.isEnabled()) return;
        long now = System.currentTimeMillis();
        for (var run : runs.findByDueAtLessThanEqualOrderByCreatedAtAsc(now, PageRequest.of(0, 100))) {
            if (run.leaseUntil > now) continue;
            // A new wake-up can be sent for each due poll; run fencing prevents concurrent work
            // on the same job. The five-minute watchdog repairs an accepted but lost message.
            if (queue.send(run.id, "AWS_SECURITY_" + run.id, run.id + "-" + now / 10000)) persistence.dispatchRecorded(run.id);
        }
    }
    @Scheduled(fixedDelayString = "${watchtower.aws-security.poll-ms:2000}")
    public void poll() {
        if (!queue.isEnabled() || !slot.tryAcquire()) return;
        var messages = queue.receive(1, 1);
        if (messages.isEmpty()) { slot.release(); return; }
        var message = messages.getFirst();
        worker.execute(() -> {
            try {
                if (!message.body().matches("[a-f0-9-]{36}") || !runs.existsById(message.body())) { queue.delete(message.receiptHandle()); return; }
                long deadline = System.currentTimeMillis() + 5 * 3600000L;
                Runnable beat = () -> { if (!queue.changeVisibility(message.receiptHandle(), 180)) throw new IllegalStateException("AWS queue lease lost"); };
                beat.run();
                // This receipt is only a wake-up. A full AWS account never holds the worker;
                // the saved due time retries the queued assessment later.
                if (!coordinator.run(message.body(), beat, deadline)) persistence.scheduleCapacityRetry(message.body());
                queue.delete(message.receiptHandle());
            } catch (RuntimeException e) { /* Durable intent and receipt redelivery retain recovery ownership. */ }
            finally { slot.release(); }
        });
    }
    @PreDestroy public void close() { worker.shutdownNow(); if (client != null) client.close(); }
}
