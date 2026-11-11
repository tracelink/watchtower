package com.tracelink.appsec.module.awssecurity;
import org.springframework.data.jpa.repository.JpaRepository;
public interface AwsSecurityAuditRepository extends JpaRepository<AwsSecurityAudit,Long> { }
