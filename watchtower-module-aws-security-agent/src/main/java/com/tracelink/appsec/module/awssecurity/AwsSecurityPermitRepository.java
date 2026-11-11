package com.tracelink.appsec.module.awssecurity;
import org.springframework.data.jpa.repository.*;
import jakarta.persistence.LockModeType;

public interface AwsSecurityPermitRepository extends JpaRepository<AwsSecurityPermit, Integer> {
    @Lock(LockModeType.PESSIMISTIC_WRITE) @Query("select p from AwsSecurityPermit p where p.id = 1")
    AwsSecurityPermit locked();
    java.util.List<AwsSecurityPermit> findAllByOrderByIdAsc();
}
