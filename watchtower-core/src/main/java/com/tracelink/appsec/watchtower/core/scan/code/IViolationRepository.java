package com.tracelink.appsec.watchtower.core.scan.code;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

/**
 * High-level Repostiory for all Violations
 *
 * @param <V> a type describing the associated Violation
 * @author csmith
 */
@NoRepositoryBean
public interface IViolationRepository<V extends AbstractViolationEntity<?>>
		extends JpaRepository<V, Long> {
}
