package com.tracelink.appsec.watchtower.core.scan.presentation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class ScanFailureTest {

	private static final String UNMAPPABLE = "Malformed input or input contains unmappable characters: "
			+ "/tmp/ops-rpmdev-master.zip2897393623334131642/src_staging/tl-django-1.10/tests/static/test/?.txt";

	@Test
	void removesTheServersWorkingFolderButKeepsThePathInsideTheArchive() {
		String detail = ScanFailure.withoutServerPaths(UNMAPPABLE);

		assertEquals("Malformed input or input contains unmappable characters: tl-django-1.10/tests/static/test/?.txt",
				detail);
		assertFalse(detail.contains("/tmp/"));
	}

	@Test
	void removesOtherAbsoluteTemporaryPaths() {
		assertEquals("Could not open archive.zip", ScanFailure.withoutServerPaths(
				"Could not open /var/folders/x1/T/upload-123/archive.zip"));
		assertEquals("Could not open archive.zip",
				ScanFailure.withoutServerPaths("Could not open /tmp/upload-77/archive.zip"));
	}

	@Test
	void explainsAnUnreadableFileNameInPlainWords() {
		ScanFailure failure = ScanFailure.of(UNMAPPABLE);

		assertEquals("Couldn't read the archive", failure.headline());
		assertEquals("A file name inside the ZIP uses characters the server can't read. "
				+ "Re-create the ZIP with plain file names and upload it again.", failure.hint());
		assertEquals(ScanFailure.withoutServerPaths(UNMAPPABLE), failure.detail());
	}

	@Test
	void anyOtherFailureGetsAGenericLineAndKeepsItsDetail() {
		ScanFailure failure = ScanFailure.of("Scanner crashed");

		assertEquals("The scan failed", failure.headline());
		assertEquals("Upload the archive again. If it fails again, ask an administrator to check the logs.",
				failure.hint());
		assertEquals("Scanner crashed", failure.detail());
	}

	@Test
	void noMessageMeansNoFailure() {
		assertNull(ScanFailure.of(null));
		assertNull(ScanFailure.of("  "));
		assertNull(ScanFailure.withoutServerPaths(null));
	}
}
