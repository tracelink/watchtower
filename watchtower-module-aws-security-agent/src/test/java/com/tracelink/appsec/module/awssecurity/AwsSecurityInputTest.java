package com.tracelink.appsec.module.awssecurity;

import java.nio.file.*;
import java.util.*;
import java.util.zip.ZipFile;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.core.sync.RequestBody;

class AwsSecurityInputTest {
    @Test void rawPatchRefusesCredentialDeletesRenamesAndUnknownPathEncoding() throws Exception {
        for(String header:java.util.List.of("diff --git a/.env b/app.py", "diff --git a/.aws/credentials b/.aws/credentials", "diff --git \"a/escaped\\tfile\" \"b/escaped\\tfile\""))
            assertThrows(java.io.IOException.class,()->AwsSecurityInputStore.validatePatch(header.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        AwsSecurityInputStore.validatePatch("diff --git a/tests/test_app.py b/tests/test_app.py\n".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    @TempDir Path temp;
    @Test void deterministicArchiveKeepsTestsAndExcludesCredentials() throws Exception {
        var root=Files.createDirectory(temp.resolve("root"));Files.createDirectories(root.resolve("test"));Files.writeString(root.resolve("test/example.java"),"example");
        Files.writeString(root.resolve(".env"),"secret");Files.createDirectory(root.resolve(".git"));Files.writeString(root.resolve(".git/config"),"credential");
        var one=AwsSecurityInputStore.archive(root,temp.resolve("one.zip"));var two=AwsSecurityInputStore.archive(root,temp.resolve("two.zip"));
        assertEquals(one.sha256(),two.sha256());assertEquals(1,one.files());
        try(var zip=new ZipFile(one.path().toFile())) {assertNotNull(zip.getEntry("test/example.java"));assertNull(zip.getEntry(".env"));assertNull(zip.getEntry(".git/config"));}
    }
    @Test void symlinksAreRejectedBeforeUpload() throws Exception {
        var root=Files.createDirectory(temp.resolve("root"));Files.createSymbolicLink(root.resolve("escape"),temp);
        assertThrows(java.io.IOException.class,()->AwsSecurityInputStore.archive(root,temp.resolve("archive.zip")));
    }
    @Test void requiredUploadNeverAcceptsAnUnverifiedObject() throws Exception {
        var s3=mock(S3Client.class);var store=new AwsSecurityInputStore(s3);Path file=Files.writeString(temp.resolve("input"),"context");
        when(s3.putObject(any(PutObjectRequest.class),any(RequestBody.class))).thenReturn(PutObjectResponse.builder().build());
        when(s3.headObject(any(HeadObjectRequest.class))).thenReturn(HeadObjectResponse.builder().contentLength(7L).checksumSHA256("wrong").serverSideEncryption(ServerSideEncryption.AWS_KMS).build());
        assertThrows(java.io.IOException.class,()->store.put(AwsTestSupport.settings().profile(),"aws-security-inputs/test/run/source.zip",file,AwsSecurityInputStore.sha256(file)));
    }
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void readinessAcceptsTheSelectedBucketEncryptionWithoutWrites(boolean kms) {
        var s3 = mock(S3Client.class);
        var profile = profile(kms);
        when(s3.getBucketEncryption(any(GetBucketEncryptionRequest.class)))
            .thenReturn(bucketEncryption(kms ? ServerSideEncryption.AWS_KMS : ServerSideEncryption.AES256, kms ? profile.kmsKey() : null));

        assertDoesNotThrow(() -> new AwsSecurityInputStore(s3).readiness(profile));
        verify(s3).headBucket(HeadBucketRequest.builder().bucket(profile.bucket()).expectedBucketOwner(profile.account()).build());
        verify(s3).getBucketEncryption(GetBucketEncryptionRequest.builder().bucket(profile.bucket()).expectedBucketOwner(profile.account()).build());
        verifyNoMoreInteractions(s3);
    }
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void readinessRejectsMissingUnknownOrMismatchedEncryption(boolean kms) {
        var s3 = mock(S3Client.class);
        var profile = profile(kms);
        var invalid = new ArrayList<>(List.of(
            GetBucketEncryptionResponse.builder().build(),
            bucketEncryption(null, null),
            bucketEncryption(ServerSideEncryption.UNKNOWN_TO_SDK_VERSION, null),
            bucketEncryption(kms ? ServerSideEncryption.AES256 : ServerSideEncryption.AWS_KMS, profile.kmsKey())));
        if (kms) invalid.add(bucketEncryption(ServerSideEncryption.AWS_KMS, "arn:aws:kms:us-east-1:123456789012:key/other"));
        for (var response : invalid) {
            when(s3.getBucketEncryption(any(GetBucketEncryptionRequest.class))).thenReturn(response);
            assertThrows(IllegalStateException.class, () -> new AwsSecurityInputStore(s3).readiness(profile));
        }
    }
    @Test void unreadableBucketEncryptionDoesNotPassReadiness() {
        var s3 = mock(S3Client.class);
        when(s3.getBucketEncryption(any(GetBucketEncryptionRequest.class)))
            .thenThrow(S3Exception.builder().statusCode(403).build());
        assertThrows(S3Exception.class, () -> new AwsSecurityInputStore(s3).readiness(profile(false)));
    }
    @ParameterizedTest
    @CsvSource({"false, false", "false, true", "true, false", "true, true"})
    void uploadAndAcceptedWriteRecoveryVerifyTheSelectedEncryption(boolean kms, boolean alreadyExists) throws Exception {
        var s3 = mock(S3Client.class);
        var profile = profile(kms);
        var file = Files.writeString(temp.resolve("input"), "context");
        var hash = AwsSecurityInputStore.sha256(file);
        var checksum = Base64.getEncoder().encodeToString(HexFormat.of().parseHex(hash));
        var algorithm = kms ? ServerSideEncryption.AWS_KMS : ServerSideEncryption.AES256;
        if (alreadyExists) when(s3.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
            .thenThrow(S3Exception.builder().statusCode(412).build());
        when(s3.headObject(any(HeadObjectRequest.class))).thenReturn(HeadObjectResponse.builder()
            .contentLength(Files.size(file)).checksumSHA256(checksum).serverSideEncryption(algorithm)
            .ssekmsKeyId(kms ? profile.kmsKey() : null).versionId("version").build());

        var key = "aws-security-inputs/test/run/source.zip";
        assertEquals("version", new AwsSecurityInputStore(s3).put(profile, key, file, hash));
        var request = ArgumentCaptor.forClass(PutObjectRequest.class);
        verify(s3).putObject(request.capture(), any(RequestBody.class));
        assertEquals(algorithm, request.getValue().serverSideEncryption());
        assertEquals(kms ? profile.kmsKey() : null, request.getValue().ssekmsKeyId());
        assertEquals("*", request.getValue().ifNoneMatch());
        assertEquals(checksum, request.getValue().checksumSHA256());
        verify(s3).headObject(HeadObjectRequest.builder().bucket(profile.bucket()).key(key).checksumMode(ChecksumMode.ENABLED).build());
        verifyNoMoreInteractions(s3);
    }
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void recoveredObjectsWithWrongEncryptionSizeOrChecksumAreRejected(boolean kms) throws Exception {
        var s3 = mock(S3Client.class);
        var profile = profile(kms);
        var file = Files.writeString(temp.resolve("input"), "context");
        var hash = AwsSecurityInputStore.sha256(file);
        var valid = HeadObjectResponse.builder().contentLength(Files.size(file))
            .checksumSHA256(Base64.getEncoder().encodeToString(HexFormat.of().parseHex(hash)))
            .serverSideEncryption(kms ? ServerSideEncryption.AWS_KMS : ServerSideEncryption.AES256)
            .ssekmsKeyId(kms ? profile.kmsKey() : null).build();
        var invalid = new ArrayList<>(List.of(
            valid.toBuilder().serverSideEncryption((ServerSideEncryption) null).build(),
            valid.toBuilder().serverSideEncryption(kms ? ServerSideEncryption.AES256 : ServerSideEncryption.AWS_KMS).build(),
            valid.toBuilder().contentLength(0L).build(),
            valid.toBuilder().checksumSHA256("wrong").build()));
        if (kms) invalid.add(valid.toBuilder().ssekmsKeyId("arn:aws:kms:us-east-1:123456789012:key/other").build());
        when(s3.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
            .thenThrow(S3Exception.builder().statusCode(412).build());
        for (var response : invalid) {
            when(s3.headObject(any(HeadObjectRequest.class))).thenReturn(response);
            assertThrows(java.io.IOException.class, () -> new AwsSecurityInputStore(s3)
                .put(profile, "aws-security-inputs/test/run/source.zip", file, hash));
        }
    }
    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void deniedUploadsNeverFallBackToAnotherEncryptionMode(boolean kms) throws Exception {
        var s3 = mock(S3Client.class);
        var file = Files.writeString(temp.resolve("input"), "context");
        when(s3.putObject(any(PutObjectRequest.class), any(RequestBody.class)))
            .thenThrow(S3Exception.builder().statusCode(403).build());
        assertThrows(S3Exception.class, () -> new AwsSecurityInputStore(s3)
            .put(profile(kms), "aws-security-inputs/test/run/source.zip", file, AwsSecurityInputStore.sha256(file)));
        verify(s3).putObject(any(PutObjectRequest.class), any(RequestBody.class));
        verifyNoMoreInteractions(s3);
    }
    private static AwsSecuritySettings.Profile profile(boolean kms) {
        return (kms ? AwsTestSupport.settings() : AwsTestSupport.settings("")).profile();
    }
    private static GetBucketEncryptionResponse bucketEncryption(ServerSideEncryption algorithm, String key) {
        return GetBucketEncryptionResponse.builder().serverSideEncryptionConfiguration(
            ServerSideEncryptionConfiguration.builder().rules(ServerSideEncryptionRule.builder()
                .applyServerSideEncryptionByDefault(ServerSideEncryptionByDefault.builder()
                    .sseAlgorithm(algorithm).kmsMasterKeyID(key).build()).build()).build()).build();
    }
    @Test void deleteFailureIsNotReportedAsSuccess() {
        var s3=mock(S3Client.class);var store=new AwsSecurityInputStore(s3);
        when(s3.deleteObject(any(DeleteObjectRequest.class))).thenThrow(S3Exception.builder().statusCode(403).message("denied").build());
        assertThrows(S3Exception.class,()->store.delete(AwsTestSupport.settings().profile(),"aws-security-inputs/test/run/source.zip","version"));
    }
}
