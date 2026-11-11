package com.tracelink.appsec.module.awssecurity;

import jakarta.persistence.*;

/**
 * The one AWS code review kept for a repository, and the lock that serializes "point it at this scan's source, then start the
 * job". A job records its own source, so once started it no longer depends on what the review points at.
 */
@Entity @Table(name = "aws_security_repo_review")
public class AwsSecurityRepoReview {
    @Id @Column(name = "repository_id") public long repositoryId;
    @Version public long version;
    @Column(name = "space_id", nullable = false, length = 64) public String spaceId;
    @Column(nullable = false, length = 100) public String title;
    @Column(name = "review_id", length = 128) public String reviewId;
    @Column(name = "lock_owner", length = 36) public String lockOwner;
    @Column(name = "lock_until", nullable = false) public long lockUntil;
    @Column(name = "created_at", nullable = false) public long createdAt;
}
