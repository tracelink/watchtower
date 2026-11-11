package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.io.IOException;
import java.util.Optional;

/**
 * Where repository scan reports and exports are kept: S3 in a deployment, a local directory for
 * development. Objects are immutable; each scan writes its own key.
 *
 * @author Watchtower
 */
public interface RepoReportStore {

	void put(String key, byte[] content, String contentType) throws IOException;

	/**
	 * @return the object, or empty if it does not exist (for example, expired by retention)
	 */
	Optional<byte[]> get(String key) throws IOException;

	void copy(String fromKey, String toKey) throws IOException;

	/**
	 * @return true if objects are visible to every pod
	 */
	boolean isShared();

	/**
	 * @param apiLabel   the integration
	 * @param repository the repository name
	 * @param scanId     the scan
	 * @return the key of the scan's report
	 */
	static String reportKey(String apiLabel, String repository, long scanId) {
		return "reports/repository/" + safe(apiLabel) + "/" + safe(repository) + "/" + scanId
				+ ".json.gz";
	}

	/**
	 * @param jobId  the export job
	 * @param format the file extension
	 * @return the key of the export's file
	 */
	static String exportKey(long jobId, String format) {
		return "exports/" + jobId + "." + safe(format);
	}

	/**
	 * Keeps a key segment to plain characters, so a name from the SCM can never add path
	 * segments or escape the prefix.
	 */
	static String safe(String segment) {
		String cleaned = segment == null ? "" : segment.replaceAll("[^A-Za-z0-9._-]", "_");
		return cleaned.isEmpty() || cleaned.chars().allMatch(c -> c == '.') ? "_" : cleaned;
	}
}
