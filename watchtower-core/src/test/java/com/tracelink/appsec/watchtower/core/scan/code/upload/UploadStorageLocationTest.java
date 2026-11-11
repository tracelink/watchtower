package com.tracelink.appsec.watchtower.core.scan.code.upload;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Test;

public class UploadStorageLocationTest {

	@Test
	public void testForS3KeyRoundTrips() {
		String storageKey = UploadStorageLocation.forS3Key("uploads/abc.zip");

		assertTrue(UploadStorageLocation.isS3(storageKey));
		assertEquals("uploads/abc.zip", UploadStorageLocation.s3Key(storageKey));
	}

	@Test
	public void testForLocalPathRoundTrips() {
		Path path = Paths.get("some", "path", "upload.zip");
		String storageKey = UploadStorageLocation.forLocalPath(path);

		assertFalse(UploadStorageLocation.isS3(storageKey));
		assertEquals(path.toAbsolutePath(), UploadStorageLocation.localPath(storageKey));
	}

	@Test
	public void testUnprefixedKeyIsTreatedAsLocal() {
		// Pre-3.4 rows in upload_container are bare absolute local paths with no
		// prefix at all.
		String legacyLocalPath = "/var/watchtower/upload/somefile";

		assertFalse(UploadStorageLocation.isS3(legacyLocalPath));
		assertEquals(Paths.get(legacyLocalPath), UploadStorageLocation.localPath(legacyLocalPath));
	}

	@Test
	public void testIsS3ReturnsFalseForNull() {
		assertFalse(UploadStorageLocation.isS3(null));
	}
}
