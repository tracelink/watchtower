package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.io.IOException;
import java.util.Optional;

import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;

/**
 * Reports in the Watchtower S3 bucket. Retention is an S3 lifecycle rule on the
 * {@code reports/} and {@code exports/} prefixes, not application code.
 *
 * @author Watchtower
 */
public class S3RepoReportStore implements RepoReportStore {

	private final S3Service s3;

	public S3RepoReportStore(S3Service s3) {
		this.s3 = s3;
	}

	@Override
	public void put(String key, byte[] content, String contentType) throws IOException {
		s3.putBytes(key, content, contentType);
	}

	@Override
	public Optional<byte[]> get(String key) throws IOException {
		return Optional.ofNullable(s3.getBytes(key));
	}

	@Override
	public void copy(String fromKey, String toKey) throws IOException {
		s3.copyObject(fromKey, toKey);
	}

	@Override
	public boolean isShared() {
		return true;
	}
}
