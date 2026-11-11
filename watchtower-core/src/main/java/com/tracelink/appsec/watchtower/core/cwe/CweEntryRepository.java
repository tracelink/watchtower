package com.tracelink.appsec.watchtower.core.cwe;

import org.springframework.data.jpa.repository.JpaRepository;

public interface CweEntryRepository extends JpaRepository<CweEntryEntity, Integer> {
}
