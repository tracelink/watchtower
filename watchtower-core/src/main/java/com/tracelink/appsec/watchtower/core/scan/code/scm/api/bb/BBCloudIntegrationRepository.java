package com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Repository for the Bitbucket Cloud Integration API
 *
 * @author mcool
 *
 */
@Repository(value = "bbCloudIntegrationRepository")
public interface BBCloudIntegrationRepository extends
		JpaRepository<BBCloudIntegrationEntity, Long> {

}
