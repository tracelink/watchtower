package com.tracelink.appsec.watchtower.core.scan.code.upload;

import java.nio.file.Path;

/**
 * Encodes where an uploaded scan's zip is stored - S3, or local disk as a fallback
 * when S3 is not configured - as a single prefixed string persisted in
 * {@code UploadScanContainerEntity}'s storage-key column. The scheme is embedded per
 * row rather than inferred from the current {@code S3Service} configuration, so a row
 * written while S3 was unconfigured still resolves correctly if S3 is turned on later
 * (or vice versa).
 * <p>
 * A string with no recognized prefix is treated as a local path. Every row written
 * before this class existed is unprefixed: pre-upload-to-S3 rows hold a genuine
 * absolute local path, so this is correct for them. Rows written during the brief
 * window where upload storage was S3-only (no local fallback) hold a bare S3 key like
 * {@code "uploads/<uuid>.zip"} - misreading one of those as a local (relative,
 * nonexistent) path means downtime recovery marks it failed with "no longer exists"
 * instead of recovering it from S3. That is accepted as a one-time, dev-only cost of
 * adding the fallback after the fact, not something this class tries to disambiguate.
 *
 * @author Watchtower
 */
public final class UploadStorageLocation {

	private static final String S3_PREFIX = "s3:";
	private static final String LOCAL_PREFIX = "file:";

	private UploadStorageLocation() {
	}

	/**
	 * @param key an S3 object key
	 * @return the storage key to persist for an upload stored in S3
	 */
	public static String forS3Key(String key) {
		return S3_PREFIX + key;
	}

	/**
	 * @param path a local file path
	 * @return the storage key to persist for an upload stored on local disk
	 */
	public static String forLocalPath(Path path) {
		return LOCAL_PREFIX + path.toAbsolutePath();
	}

	/**
	 * @param storageKey a persisted storage key
	 * @return true if this key refers to an object in S3
	 */
	public static boolean isS3(String storageKey) {
		return storageKey != null && storageKey.startsWith(S3_PREFIX);
	}

	/**
	 * @param storageKey a persisted storage key for which {@link #isS3(String)} is true
	 * @return the underlying S3 object key
	 */
	public static String s3Key(String storageKey) {
		return storageKey.substring(S3_PREFIX.length());
	}

	/**
	 * @param storageKey a persisted storage key for which {@link #isS3(String)} is
	 *                   false
	 * @return the underlying local file path
	 */
	public static Path localPath(String storageKey) {
		if (storageKey.startsWith(LOCAL_PREFIX)) {
			return Path.of(storageKey.substring(LOCAL_PREFIX.length()));
		}
		return Path.of(storageKey);
	}
}
