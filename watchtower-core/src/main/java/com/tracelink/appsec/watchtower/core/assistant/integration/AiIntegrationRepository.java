package com.tracelink.appsec.watchtower.core.assistant.integration;

import org.springframework.data.jpa.repository.*;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

/** Also what lets key rotation find and re-encrypt AI provider keys. */
public interface AiIntegrationRepository extends JpaRepository<AiIntegrationEntity,AiProvider> {
 /** Records a connection check without touching the key or the version an admin's form holds. */
 @Transactional @Modifying(clearAutomatically=true)
 @Query("UPDATE AiIntegrationEntity e SET e.healthCheckedAt=:at,e.healthOk=:ok,e.healthError=:error WHERE e.provider=:provider")
 int recordHealth(@Param("provider")AiProvider provider,@Param("at")long at,@Param("ok")boolean ok,@Param("error")String error);
}
