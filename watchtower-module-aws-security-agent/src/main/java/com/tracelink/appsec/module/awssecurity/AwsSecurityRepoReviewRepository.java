package com.tracelink.appsec.module.awssecurity;

import jakarta.persistence.LockModeType;
import java.util.Optional;
import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;

public interface AwsSecurityRepoReviewRepository extends JpaRepository<AwsSecurityRepoReview, Long> {
    @Lock(LockModeType.PESSIMISTIC_WRITE) @Query("select r from AwsSecurityRepoReview r where r.repositoryId = :id")
    Optional<AwsSecurityRepoReview> locked(@Param("id") long repositoryId);
}
