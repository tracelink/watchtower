package com.tracelink.appsec.watchtower.core.scan;

import java.util.List;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.NoRepositoryBean;

/**
 * High-level Repostiory for all Scans
 *
 * @param <S> a type describing the associated Scan
 * @author csmith
 */
@NoRepositoryBean
public interface IScanRepository<S extends AbstractScanEntity<?, ?>>
		extends JpaRepository<S, Long> {

	S findById(long id);

	S findFirstByOrderByEndDateAsc();

	List<S> findByStatus(ScanStatus status);

	Page<S> findByStatusIn(List<ScanStatus> status, Pageable pageable);

	Page<S> findAllByEndDateBetween(long start, long end, Pageable pageable);
}
