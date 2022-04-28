package com.tracelink.appsec.watchtower.core.scan.image.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.tracelink.appsec.watchtower.core.scan.image.entity.AdvisoryEntity;

@Repository("advisoryRepository")
public interface AdvisoryRepository extends JpaRepository<AdvisoryEntity, Long> {

	AdvisoryEntity findByAdvisoryName(String advisoryName);

}
