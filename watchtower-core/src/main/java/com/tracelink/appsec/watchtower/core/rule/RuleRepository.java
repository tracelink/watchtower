package com.tracelink.appsec.watchtower.core.rule;

import java.util.Collection;
import java.util.List;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Repository JPA for the rule entities.
 *
 * @author mcool
 */
@Repository
public interface RuleRepository extends JpaRepository<RuleEntity, Long> {
    RuleEntity findByName(String name);

    List<RuleEntity> findByNameIn(Collection<String> names);

    /** Ids of rules stored as one entity subclass (a module's rules), lowest first. */
    @Query("SELECT r.id FROM RuleEntity r WHERE TYPE(r) = :type ORDER BY r.id")
    List<Long> findIdsByType(@Param("type") Class<? extends RuleEntity> type, Pageable page);
}
