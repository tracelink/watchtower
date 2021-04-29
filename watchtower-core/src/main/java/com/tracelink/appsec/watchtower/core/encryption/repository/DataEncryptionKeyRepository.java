package com.tracelink.appsec.watchtower.core.encryption.repository;

import com.tracelink.appsec.watchtower.core.encryption.model.DataEncryptionKey;
import java.util.Optional;
import javax.persistence.QueryHint;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.QueryHints;
import org.springframework.stereotype.Repository;

/**
 * Repository for {@link DataEncryptionKey} entities. The flush mode is configured as commit to
 * prevent excessive flushing when reading from this table. This table must be accessed during
 * reads and writes for entities with encrypted attributes, and flushing the data encryption keys
 * would disrupt those other processes.
 *
 * @author mcool
 */
@Repository
public interface DataEncryptionKeyRepository extends JpaRepository<DataEncryptionKey, Long> {

	@QueryHints(value = {
			@QueryHint(name = org.hibernate.annotations.QueryHints.FLUSH_MODE, value = "COMMIT")})
	Optional<DataEncryptionKey> findByConverterClassName(String converterClassName);
}
