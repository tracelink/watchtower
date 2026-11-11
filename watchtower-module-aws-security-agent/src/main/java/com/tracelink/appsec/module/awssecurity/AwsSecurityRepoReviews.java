package com.tracelink.appsec.module.awssecurity;

import java.util.Objects;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Remembers each repository's AWS review and holds the lock that keeps two scans of one repository from interleaving "point the
 * review at my source" and "start my job". The lock is a lease on a database row, so a crashed worker cannot hold it for ever;
 * a holder that lost its lease must stop before touching the review again.
 */
@Service
public class AwsSecurityRepoReviews {
    /** Longer than the worst case of the two AWS calls with their retries; every step of the holder extends it. */
    static final long LEASE_MS = 10 * 60_000L;
    /** What a scan learns when it asks for the lock: whether it holds it, and the review to reuse, if one exists. */
    public record Claim(boolean held, String reviewId) {
        static final Claim WAITING = new Claim(false, null);
    }
    private final AwsSecurityRepoReviewRepository repository;
    private final TransactionTemplate tx;
    public AwsSecurityRepoReviews(AwsSecurityRepoReviewRepository repository, PlatformTransactionManager transactions) {
        this.repository = repository; this.tx = new TransactionTemplate(transactions);
    }
    /** Takes (or keeps) the repository's lock for this run. Waiting is a normal answer, not an error. */
    public Claim acquire(long repositoryId, String spaceId, String title, String runId, long now) {
        try { return tx.execute(status -> claim(repositoryId, spaceId, title, runId, now)); }
        catch (RuntimeException failure) {
            // Another scan inserted the first row at the same moment: it holds the lock, so this one waits. Anything else is real.
            if (isDuplicateKey(failure)) return Claim.WAITING;
            throw failure;
        }
    }
    /** Spring translates the exception in production; the cause chain is checked so the answer does not depend on that. */
    private static boolean isDuplicateKey(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause())
            if (t instanceof DataIntegrityViolationException || t instanceof org.hibernate.exception.ConstraintViolationException) return true;
        return false;
    }
    private Claim claim(long repositoryId, String spaceId, String title, String runId, long now) {
        var row = repository.locked(repositoryId).orElse(null);
        if (row == null) {
            row = new AwsSecurityRepoReview();
            row.repositoryId = repositoryId; row.spaceId = spaceId; row.title = title; row.createdAt = now;
            take(row, runId, now);
            repository.saveAndFlush(row);
            return new Claim(true, null);
        }
        boolean free = row.lockOwner == null || row.lockOwner.equals(runId) || row.lockUntil < now;
        if (!free) return Claim.WAITING;
        if (!Objects.equals(row.spaceId, spaceId)) { row.spaceId = spaceId; row.reviewId = null; } // A review of another agent space is not ours to reuse.
        row.title = title;
        take(row, runId, now);
        repository.saveAndFlush(row);
        return new Claim(true, row.reviewId);
    }
    private static void take(AwsSecurityRepoReview row, String runId, long now) { row.lockOwner = runId; row.lockUntil = now + LEASE_MS; }
    /** True while this run still holds the lock; asking extends the lease. A false answer means it must stop and ask again. */
    public boolean holds(long repositoryId, String runId, long now) {
        return Boolean.TRUE.equals(tx.execute(status -> {
            var row = repository.locked(repositoryId).orElse(null);
            if (row == null || !runId.equals(row.lockOwner) || row.lockUntil < now) return false;
            row.lockUntil = now + LEASE_MS; repository.saveAndFlush(row); return true;
        }));
    }
    public void recordReview(long repositoryId, String runId, String reviewId) {
        tx.executeWithoutResult(status -> repository.locked(repositoryId).filter(r -> runId.equals(r.lockOwner)).ifPresent(r -> {
            r.reviewId = reviewId; repository.saveAndFlush(r);
        }));
    }
    /** AWS no longer has the review (it was deleted there): the next scan creates a new one. */
    public void forgetReview(long repositoryId, String runId) {
        tx.executeWithoutResult(status -> repository.locked(repositoryId).filter(r -> runId.equals(r.lockOwner)).ifPresent(r -> {
            r.reviewId = null; repository.saveAndFlush(r);
        }));
    }
    public void release(long repositoryId, String runId) {
        tx.executeWithoutResult(status -> repository.locked(repositoryId).filter(r -> runId.equals(r.lockOwner)).ifPresent(r -> {
            r.lockOwner = null; r.lockUntil = 0; repository.saveAndFlush(r);
        }));
    }
}
