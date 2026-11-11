package com.tracelink.appsec.watchtower.core.rule.report;

import java.util.Collection;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface ThemeNameRepository extends JpaRepository<ThemeNameEntity,String> {
 List<ThemeNameEntity> findByThemeFingerprintInOrderByCreatedAtDesc(Collection<String> fingerprints);
 @Transactional @Modifying
 @Query("UPDATE ThemeNameEntity t SET t.lastUsedAt=:now WHERE t.themeFingerprint IN :fingerprints")
 int touch(@Param("fingerprints") Collection<String> fingerprints,@Param("now") long now);
 @Transactional @Modifying
 @Query("DELETE FROM ThemeNameEntity t WHERE t.lastUsedAt<:before")
 int deleteUnusedBefore(@Param("before") long before);
}
