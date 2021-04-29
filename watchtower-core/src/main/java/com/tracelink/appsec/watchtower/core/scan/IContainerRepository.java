package com.tracelink.appsec.watchtower.core.scan;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

/**
 * High-level repository interface for all {@linkplain AbstractScanContainer}s
 * 
 * @author csmith
 *
 * @param <C> The Scan Container Type
 */
@NoRepositoryBean
public interface IContainerRepository<C extends AbstractScanContainer<?>>
		extends JpaRepository<C, Long> {

}
