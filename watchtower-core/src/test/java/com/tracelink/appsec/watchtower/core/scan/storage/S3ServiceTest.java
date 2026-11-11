package com.tracelink.appsec.watchtower.core.scan.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * IMPROVEMENT_PLAN.md item 3.2's test requirements: no-op mode when unconfigured, and
 * mocked {@link S3Client} behavior for upload/download/exists when configured.
 */
public class S3ServiceTest {

	@Test
	public void assistantDeletionPreservesSafeProviderDiagnosticsForRetention() {
		S3Client client = mock(S3Client.class);
		var denied = S3Exception.builder().statusCode(403).message("private response").build();
		given(client.listObjectVersions(any(software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest.class)))
				.willThrow(denied);
		var failure = org.junit.jupiter.api.Assertions.assertThrows(java.io.IOException.class,
				() -> new S3Service("bucket", client).expireAssistantVersions("key"));
		org.junit.jupiter.api.Assertions.assertSame(denied, failure.getCause());
		assertEquals("Assistant storage expiry failed", failure.getMessage());
	}

	@Test
	public void testNoOpModeWhenBucketBlank() throws Exception {
		S3Service service = new S3Service("", "us-east-1");

		assertFalse(service.isEnabled());
		assertFalse(service.keyExists("any-key"));
		assertFalse(service.downloadZip("any-key", Files.createTempFile(null, ".zip")));
		// uploadZip/deleteObject are no-ops; the assertion here is simply that neither
		// throws with no S3Client ever constructed.
		service.uploadZip("any-key", Files.createTempFile(null, ".zip"));
		service.deleteObject("any-key");
	}

	@Test
	public void testIsEnabledWhenBucketConfigured() {
		S3Service service = new S3Service("my-bucket", mock(S3Client.class));

		assertTrue(service.isEnabled());
	}

	@Test
	public void testUploadZipCallsPutObject() throws Exception {
		S3Client mockClient = mock(S3Client.class);
		S3Service service = new S3Service("my-bucket", mockClient);
		Path zip = Files.createTempFile(null, ".zip");

		service.uploadZip("source/api/repo/abc123.zip", zip);

		verify(mockClient).putObject(any(PutObjectRequest.class), any(software.amazon.awssdk.core.sync.RequestBody.class));
	}

	@Test
	public void testKeyExistsReturnsTrueWhenHeadObjectSucceeds() {
		S3Client mockClient = mock(S3Client.class);
		S3Service service = new S3Service("my-bucket", mockClient);

		assertTrue(service.keyExists("some-key"));
		verify(mockClient).headObject(any(HeadObjectRequest.class));
	}

	@Test
	public void testKeyExistsReturnsFalseOnNoSuchKey() {
		S3Client mockClient = mock(S3Client.class);
		given(mockClient.headObject(any(HeadObjectRequest.class)))
				.willThrow(NoSuchKeyException.builder().build());
		S3Service service = new S3Service("my-bucket", mockClient);

		assertFalse(service.keyExists("missing-key"));
	}

	@Test
	public void testKeyExistsReturnsFalseOnOtherSdkFailure() {
		S3Client mockClient = mock(S3Client.class);
		given(mockClient.headObject(any(HeadObjectRequest.class)))
				.willThrow(S3Exception.builder().message("boom").build());
		S3Service service = new S3Service("my-bucket", mockClient);

		assertFalse(service.keyExists("some-key"));
	}

	@Test
	public void testDownloadZipReturnsTrueOnSuccess() throws Exception {
		S3Client mockClient = mock(S3Client.class);
		S3Service service = new S3Service("my-bucket", mockClient);
		Path target = Files.createTempFile(null, ".zip");

		assertTrue(service.downloadZip("some-key", target));
		verify(mockClient).getObject(any(GetObjectRequest.class), any(Path.class));
	}

	/** A client that, like the real SDK, refuses to write to a path that already exists. */
	private static S3Client clientThatWritesNewFilesOnly() throws Exception {
		S3Client client = mock(S3Client.class);
		given(client.getObject(any(GetObjectRequest.class), any(Path.class))).willAnswer(call -> {
			Path target = call.getArgument(1);
			Files.writeString(target, "zip-bytes", StandardOpenOption.CREATE_NEW);
			return null;
		});
		return client;
	}

	@Test
	public void testDownloadRequiredReplacesTheTempFileTheCallerJustCreated() throws Exception {
		S3Service service = new S3Service("my-bucket", clientThatWritesNewFilesOnly());
		Path target = Files.createTempFile(null, ".zip");

		service.downloadRequired("uploads/some.zip", target);

		assertEquals("zip-bytes", Files.readString(target));
	}

	@Test
	public void testDownloadZipReplacesTheTempFileTheCallerJustCreated() throws Exception {
		S3Service service = new S3Service("my-bucket", clientThatWritesNewFilesOnly());
		Path target = Files.createTempFile(null, ".zip");

		assertTrue(service.downloadZip("some-key", target));
		assertEquals("zip-bytes", Files.readString(target));
	}

	@Test
	public void testDownloadZipReturnsFalseOnCacheMiss() throws Exception {
		S3Client mockClient = mock(S3Client.class);
		given(mockClient.getObject(any(GetObjectRequest.class), any(Path.class)))
				.willThrow(NoSuchKeyException.builder().build());
		S3Service service = new S3Service("my-bucket", mockClient);

		assertFalse(service.downloadZip("missing-key", Files.createTempFile(null, ".zip")));
	}

	@Test
	public void testDownloadZipReturnsFalseOnOtherSdkFailure() throws Exception {
		S3Client mockClient = mock(S3Client.class);
		given(mockClient.getObject(any(GetObjectRequest.class), any(Path.class)))
				.willThrow(S3Exception.builder().message("boom").build());
		S3Service service = new S3Service("my-bucket", mockClient);

		assertFalse(service.downloadZip("some-key", Files.createTempFile(null, ".zip")));
	}

	@Test
	public void testDeleteObjectCallsDeleteObject() {
		S3Client mockClient = mock(S3Client.class);
		S3Service service = new S3Service("my-bucket", mockClient);

		service.deleteObject("some-key");

		verify(mockClient).deleteObject(any(DeleteObjectRequest.class));
	}

	@Test
	public void testDeleteObjectSwallowsSdkFailure() {
		S3Client mockClient = mock(S3Client.class);
		given(mockClient.deleteObject(any(DeleteObjectRequest.class)))
				.willThrow(S3Exception.builder().message("boom").build());
		S3Service service = new S3Service("my-bucket", mockClient);

		// Must not throw.
		service.deleteObject("some-key");
	}
}
