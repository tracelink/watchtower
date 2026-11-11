package com.tracelink.appsec.module.awssecurity;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.zip.*;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.core.sync.RequestBody;
import com.tracelink.appsec.module.awssecurity.AwsSecuritySettings.Profile;

/** Required, checksum-verified SSE-S3 or SSE-KMS writes. Keys are allocated durably before uploading. */
@Component
public class AwsSecurityInputStore implements AutoCloseable {
    public static final long MAX_ARCHIVE = 64L * 1024 * 1024, MAX_EXPANDED = 256L * 1024 * 1024, MAX_FILE = 8L * 1024 * 1024;
    public static final int MAX_FILES = 10000, MAX_DIFF = 5 * 1024 * 1024;
    /** The source is over a size limit (one file, all files together, or the file count); nothing was sent to AWS. */
    public static final class SourceLimitExceeded extends IOException {
        public SourceLimitExceeded() { super("AWS source limits exceeded"); }
    }
    public static final Set<String> EXCLUDED = Set.of(".git", ".svn", "node_modules", "vendor", "target", "build", "dist", ".aws", ".ssh", ".env");
    private final S3Client s3;
    @Autowired public AwsSecurityInputStore(AwsSecuritySettings settings) {
        this(S3Client.builder().region(Region.of(settings.region().isBlank() ? "us-east-1" : settings.region()))
            .credentialsProvider(DefaultCredentialsProvider.builder().build())
            .overrideConfiguration(c -> c.apiCallTimeout(Duration.ofSeconds(60)).apiCallAttemptTimeout(Duration.ofSeconds(40))).build());
    }
    public AwsSecurityInputStore(S3Client s3) { this.s3 = s3; }
    public void readiness(Profile p) {
        s3.headBucket(HeadBucketRequest.builder().bucket(p.bucket()).expectedBucketOwner(p.account()).build());
        var encryption = s3.getBucketEncryption(GetBucketEncryptionRequest.builder().bucket(p.bucket()).expectedBucketOwner(p.account()).build());
        if (encryption.serverSideEncryptionConfiguration() == null || encryption.serverSideEncryptionConfiguration().rules().stream()
                .noneMatch(r -> r.applyServerSideEncryptionByDefault() != null
                    && r.applyServerSideEncryptionByDefault().sseAlgorithm() == encryption(p)
                    && (!p.usesKms() || p.kmsKey().equals(r.applyServerSideEncryptionByDefault().kmsMasterKeyID()))))
            throw new IllegalStateException("Expected default " + (p.usesKms() ? "SSE-KMS" : "SSE-S3") + " bucket encryption unavailable");
    }
    private static ServerSideEncryption encryption(Profile p) {
        return p.usesKms() ? ServerSideEncryption.AWS_KMS : ServerSideEncryption.AES256;
    }
    public record Archive(Path path, String sha256, long bytes, int files, List<AwsSecuritySourceIndex.File> index) { }
    public static Archive archive(Path root, Path output) throws IOException {
        long expanded = 0; int count = 0;
        List<AwsSecuritySourceIndex.File> index = new ArrayList<>();
        try (var zip = new ZipOutputStream(Files.newOutputStream(output)); var paths = Files.walk(root)) {
            for (var path : paths.sorted().toList()) {
                if (path.equals(root)) continue;
                if (Files.isSymbolicLink(path)) throw new IOException("Symlinks are unsupported in AWS source inputs");
                if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) continue;
                String relative = root.relativize(path).toString().replace('\\', '/');
                if (excluded(relative)) continue;
                if (!com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails.Location.valid(relative, 1, 1)) throw new IOException("Unsafe archive path");
                long size = Files.size(path);
                if (size > MAX_FILE || (expanded += size) > MAX_EXPANDED || ++count > MAX_FILES) throw new SourceLimitExceeded();
                var fileDigest = digest();
                var entry = new ZipEntry(relative); entry.setTime(0); zip.putNextEntry(entry);
                try (var input = Files.newInputStream(path)) {
                    byte[] buffer = new byte[8192]; long read = 0; int n;
                    while ((n = input.read(buffer)) != -1) {
                        if ((read += n) > size) throw new IOException("Source changed during archive");
                        zip.write(buffer, 0, n); fileDigest.update(buffer, 0, n);
                    }
                    if (read != size) throw new IOException("Source changed during archive");
                }
                zip.closeEntry();
                index.add(new AwsSecuritySourceIndex.File(relative, HexFormat.of().formatHex(fileDigest.digest()), size));
                if (Files.size(output) > MAX_ARCHIVE) throw new IOException("AWS compressed source limit exceeded");
            }
        }
        if (count == 0 || Files.size(output) > MAX_ARCHIVE) throw new IOException("Empty or oversized AWS source archive");
        return new Archive(output, sha256(output), Files.size(output), count, List.copyOf(index));
    }
    static boolean excluded(String path) {
        return Arrays.stream(path.split("/")).anyMatch(p -> EXCLUDED.contains(p) || p.startsWith(".env.")
            || p.endsWith(".pem") || p.endsWith(".key") || p.endsWith(".p12") || p.endsWith(".class")
            || p.endsWith(".jar") || p.endsWith(".zip") || p.endsWith(".png") || p.endsWith(".jpg"));
    }
    static void validatePatch(byte[] patch) throws IOException {
        if (patch.length == 0 || patch.length > MAX_DIFF) throw new IOException("Empty or oversized differential input");
        var header = java.util.regex.Pattern.compile("^diff --git a/(.+?) b/(.+)$");
        int files = 0;
        for (String line : new String(patch, java.nio.charset.StandardCharsets.UTF_8).split("\n")) {
            if (!line.startsWith("diff --git ")) continue;
            var paths = header.matcher(line);
            if (!paths.matches() || ++files > 3000) throw new IOException("Unsupported diff path encoding or file bound");
            // Inspect both paths: deleting or renaming a credential file still exposes its old source.
            for (int side = 1; side <= 2; side++) {
                String path = paths.group(side);
                if (excluded(path) || !com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails.Location.valid(path, 1, 1))
                    throw new IOException("Exact patch includes an excluded or unsafe path; export refused");
            }
        }
        if (files == 0) throw new IOException("No supported differential file headers");
    }
    public String put(Profile p, String key, Path file, String hash) throws IOException {
        String checksum = Base64.getEncoder().encodeToString(HexFormat.of().parseHex(hash));
        var request = PutObjectRequest.builder().bucket(p.bucket()).key(key).ifNoneMatch("*")
            .serverSideEncryption(encryption(p)).checksumSHA256(checksum).metadata(Map.of("sha256", hash));
        if (p.usesKms()) request.ssekmsKeyId(p.kmsKey());
        try {
            s3.putObject(request.build(), RequestBody.fromFile(file));
        } catch (S3Exception e) { if (e.statusCode() != 412) throw e; }
        // Also covers a previous accepted write whose response was lost. Never overwrite.
        var head = s3.headObject(HeadObjectRequest.builder().bucket(p.bucket()).key(key).checksumMode(ChecksumMode.ENABLED).build());
        if (head.contentLength() != Files.size(file) || !checksum.equals(head.checksumSHA256())
                || head.serverSideEncryption() != encryption(p) || (p.usesKms() && !p.kmsKey().equals(head.ssekmsKeyId())))
            throw new IOException("AWS input verification failed");
        return head.versionId();
    }
    public void delete(Profile p, String key, String version) {
        if (key == null) return;
        if (!key.startsWith("aws-security-inputs/" + p.installation() + "/")) throw new IllegalArgumentException("Invalid input key");
        s3.deleteObject(DeleteObjectRequest.builder().bucket(p.bucket()).key(key).versionId(version).build());
        // Handle accepted-upload timeouts and versioned buckets, including delete markers.
        String keyMarker = null, versionMarker = null;
        Set<String> markers = new HashSet<>();
        do {
            var page = s3.listObjectVersions(ListObjectVersionsRequest.builder().bucket(p.bucket()).prefix(key)
                .keyMarker(keyMarker).versionIdMarker(versionMarker).build());
            page.versions().stream().filter(v -> key.equals(v.key())).forEach(v -> s3.deleteObject(
                DeleteObjectRequest.builder().bucket(p.bucket()).key(key).versionId(v.versionId()).build()));
            page.deleteMarkers().stream().filter(v -> key.equals(v.key())).forEach(v -> s3.deleteObject(
                DeleteObjectRequest.builder().bucket(p.bucket()).key(key).versionId(v.versionId()).build()));
            if (!Boolean.TRUE.equals(page.isTruncated())) break;
            keyMarker = page.nextKeyMarker(); versionMarker = page.nextVersionIdMarker();
            if (keyMarker == null || !markers.add(keyMarker + ":" + versionMarker) || markers.size() > 1000)
                throw new IllegalStateException("Input version listing did not terminate");
        } while (keyMarker != null);
        try { s3.headObject(HeadObjectRequest.builder().bucket(p.bucket()).key(key).build()); throw new IllegalStateException("Input deletion not confirmed"); }
        catch (S3Exception e) { if (e.statusCode() != 404) throw e; }
    }
    static MessageDigest digest() { try { return MessageDigest.getInstance("SHA-256"); } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); } }
    static String sha256(byte[] bytes) { return HexFormat.of().formatHex(digest().digest(bytes)); }
    public static String sha256(Path path) throws IOException {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            try (var input = Files.newInputStream(path)) { byte[] b = new byte[8192]; int n; while ((n = input.read(b)) != -1) digest.update(b, 0, n); }
            return HexFormat.of().formatHex(digest.digest());
        } catch (java.security.NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
    public void close() { s3.close(); }
}
