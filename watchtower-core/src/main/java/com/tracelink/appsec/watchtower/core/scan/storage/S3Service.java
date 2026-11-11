package com.tracelink.appsec.watchtower.core.scan.storage;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkException;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

/**
 * Wraps S3 access for the source-zip cache (IMPROVEMENT_PLAN.md item 3.3) and, once
 * items 3.4/3.5 land, upload storage. Uses IRSA exclusively - never a static access
 * key/secret - via {@link DefaultCredentialsProvider}, which resolves the pod's
 * {@code ServiceAccount}-bound role in the cluster and a local AWS profile/env vars
 * everywhere else.
 * <p>
 * Operates in no-op mode when {@code watchtower.storage.s3.bucket} is blank: every
 * method becomes a safe no-op (uploads skip, existence checks return false) rather than
 * building an {@link S3Client} that would fail the first time it tried to resolve
 * credentials. This is what lets the app start in dev/test without any AWS
 * configuration at all.
 *
 * @author Watchtower
 */
@Service
public class S3Service {
	private static final Logger LOG = LoggerFactory.getLogger(S3Service.class);

	private final String bucket;
	private final S3Client s3Client;

	@Autowired
	public S3Service(@Value("${watchtower.storage.s3.bucket:}") String bucket,
			@Value("${watchtower.storage.s3.region:us-east-1}") String region) {
		this.bucket = bucket;
		this.s3Client = bucket.isBlank() ? null
				: S3Client.builder().region(Region.of(region))
						.credentialsProvider(DefaultCredentialsProvider.create()).build();
	}

	/**
	 * Test-only seam: lets tests (in this package and {@code scan.code.scm.pr}, where
	 * {@code PRScanAgentTest} exercises the item 3.3 cache path) inject a mocked
	 * {@link S3Client} directly, since the {@code @Value}-based constructor's real
	 * client can't be exercised against a real AWS endpoint in a unit test.
	 *
	 * @param bucket   the bucket to operate against
	 * @param s3Client the client to use, or null for no-op mode
	 */
	public S3Service(String bucket, S3Client s3Client) {
		this.bucket = bucket;
		this.s3Client = s3Client;
	}

	/**
	 * @return true if a bucket is configured and this service will actually talk to S3
	 */
	public boolean isEnabled() {
		return s3Client != null;
	}

	/**
	 * Uploads a local zip file to the given S3 key. Best-effort: a failure is logged and
	 * swallowed rather than thrown, since every current caller (item 3.3's cache write)
	 * treats S3 as a cache, not a hard dependency - a failed cache write must never fail
	 * the scan that produced it.
	 *
	 * @param key      the destination object key
	 * @param localZip the local zip file to upload
	 */
	public void uploadZip(String key, Path localZip) {
		if (s3Client == null) {
			return;
		}
		try {
			s3Client.putObject(PutObjectRequest.builder().bucket(bucket).key(key).build(),
					RequestBody.fromFile(localZip));
		} catch (SdkException e) {
			LOG.warn("Failed to upload " + key + " to S3 bucket " + bucket, e);
		}
	}

	/**
	 * Downloads the object at the given key to a local path.
	 *
	 * @param key         the object key to fetch
	 * @param localTarget where to write the downloaded file
	 * @return true if the object existed and was downloaded; false on a cache miss or
	 *         any S3 failure, so callers can fall back to their non-S3 source
	 */
	public boolean downloadZip(String key, Path localTarget) {
		if (s3Client == null) {
			return false;
		}
		try {
			fetchInto(key, localTarget);
			return true;
		} catch (NoSuchKeyException e) {
			return false;
		} catch (SdkException | IOException e) {
			LOG.warn("Failed to download " + key + " from S3 bucket " + bucket
					+ "; treating as a cache miss", e);
			return false;
		}
	}

	/**
	 * Writes the object to {@code localTarget}. The SDK refuses to write over a file that
	 * already exists, and callers pass a temp file they have just created, so the path is
	 * cleared first.
	 */
	private void fetchInto(String key, Path localTarget) throws IOException {
		Files.deleteIfExists(localTarget);
		s3Client.getObject(GetObjectRequest.builder().bucket(bucket).key(key).build(),
				localTarget);
	}

	/**
	 * Uploads content to the given S3 key, throwing on any failure - including when no
	 * bucket is configured. Unlike {@link #uploadZip(String, Path)} (a best-effort cache
	 * write for item 3.3), this is item 3.4's upload storage: the only copy of the data
	 * the caller has, so a failure must surface as an error rather than silently losing
	 * the upload. There is deliberately no local-disk fallback, so an unconfigured
	 * bucket is treated the same as any other upload failure.
	 *
	 * @param key           the destination object key
	 * @param content       the content to upload
	 * @param contentLength the exact length of {@code content}, required by the
	 *                      non-multipart S3 PUT API
	 * @throws IOException if no bucket is configured or the upload fails
	 */
	public void uploadRequired(String key, InputStream content, long contentLength)
			throws IOException {
		if (s3Client == null) {
			throw new IOException("S3 storage is not configured; cannot store upload");
		}
		try {
			s3Client.putObject(PutObjectRequest.builder().bucket(bucket).key(key).build(),
					RequestBody.fromInputStream(content, contentLength));
		} catch (SdkException e) {
			throw new IOException("Failed to upload " + key + " to S3 bucket " + bucket, e);
		}
	}

	/**
	 * Downloads the object at the given key to a local path, throwing on any failure.
	 * Unlike {@link #downloadZip(String, Path)} (a cache lookup where a miss is a normal
	 * outcome for item 3.3), this is item 3.4's upload storage - the only place the data
	 * is kept - so a missing object or a failed download must surface as an error
	 * instead of being treated as a fallback-and-continue case.
	 *
	 * @param key         the object key to fetch
	 * @param localTarget where to write the downloaded file
	 * @throws IOException if no bucket is configured or the download fails
	 */
	public void downloadRequired(String key, Path localTarget) throws IOException {
		if (s3Client == null) {
			throw new IOException("S3 storage is not configured; cannot retrieve upload");
		}
		try {
			fetchInto(key, localTarget);
		} catch (SdkException e) {
			throw new IOException("Failed to download " + key + " from S3 bucket " + bucket, e);
		}
	}

	/**
	 * Deletes the object at the given key, if it exists. A failure is logged and
	 * swallowed, matching {@link #uploadZip(String, Path)}'s best-effort contract.
	 *
	 * @param key the object key to delete
	 */
	/**
	 * Stores a small object (a scan report) in one request.
	 *
	 * @throws IOException if S3 is not configured or the write fails
	 */
	public void putBytes(String key, byte[] content, String contentType) throws IOException {
		if (s3Client == null) {
			throw new IOException("S3 storage is not configured; cannot store " + key);
		}
		try {
			s3Client.putObject(PutObjectRequest.builder().bucket(bucket).key(key)
					.contentType(contentType).build(), RequestBody.fromBytes(content));
		} catch (SdkException e) {
			throw new IOException("Failed to store " + key + " in S3 bucket " + bucket, e);
		}
	}

	/**
	 * @return the object's bytes, or null if it does not exist
	 * @throws IOException if S3 is not configured or the read fails
	 */
	public byte[] getBytes(String key) throws IOException {
		if (s3Client == null) {
			throw new IOException("S3 storage is not configured; cannot read " + key);
		}
		try {
			return s3Client.getObjectAsBytes(GetObjectRequest.builder().bucket(bucket).key(key)
					.build()).asByteArray();
		} catch (NoSuchKeyException e) {
			return null;
		} catch (SdkException e) {
			throw new IOException("Failed to read " + key + " from S3 bucket " + bucket, e);
		}
	}

	/**
	 * Copies an object inside the bucket without downloading it.
	 *
	 * @throws IOException if S3 is not configured or the copy fails
	 */
	public void copyObject(String fromKey, String toKey) throws IOException {
		if (s3Client == null) {
			throw new IOException("S3 storage is not configured; cannot copy " + fromKey);
		}
		try {
			s3Client.copyObject(CopyObjectRequest.builder().sourceBucket(bucket)
					.sourceKey(fromKey).destinationBucket(bucket).destinationKey(toKey).build());
		} catch (SdkException e) {
			throw new IOException("Failed to copy " + fromKey + " in S3 bucket " + bucket, e);
		}
	}

	public void deleteObject(String key) {
		if (s3Client == null) {
			return;
		}
		try {
			s3Client.deleteObject(DeleteObjectRequest.builder().bucket(bucket).key(key).build());
		} catch (SdkException e) {
			LOG.warn("Failed to delete " + key + " from S3 bucket " + bucket, e);
		}
	}

	/**
	 * @param key the object key to check
	 * @return true if the object exists in S3; false if it does not, S3 is unreachable,
	 *         or no bucket is configured
	 */
	public boolean keyExists(String key) {
		if (s3Client == null) {
			return false;
		}
		try {
			s3Client.headObject(HeadObjectRequest.builder().bucket(bucket).key(key).build());
			return true;
		} catch (NoSuchKeyException e) {
			return false;
		} catch (SdkException e) {
			LOG.warn("Failed to check existence of " + key + " in S3 bucket " + bucket
					+ "; treating as absent", e);
			return false;
		}
	}
 /** Encrypted assistant artifacts; ordinary scan-cache methods retain their existing contract. */
 public void putAssistantBytes(String key,byte[] bytes) throws IOException {
  if(s3Client==null)throw new IOException("S3 unavailable");
  try {s3Client.putObject(PutObjectRequest.builder().bucket(bucket).key(key).ifNoneMatch("*").contentType("application/gzip")
    .serverSideEncryption(software.amazon.awssdk.services.s3.model.ServerSideEncryption.AES256).build(),RequestBody.fromBytes(bytes));}
  catch(SdkException e){throw new IOException("Assistant storage write failed");}
 }
 public byte[] getBoundedBytes(String key,int max) throws IOException {
  if(s3Client==null)throw new IOException("S3 unavailable");
  try(var in=s3Client.getObject(GetObjectRequest.builder().bucket(bucket).key(key).build())) {
   if(in.response().contentLength()>max)throw new IOException("Artifact exceeds limit");
   byte[] bytes=in.readNBytes(max+1);if(bytes.length>max)throw new IOException("Artifact exceeds limit");return bytes;
  } catch(SdkException e){throw new IOException("Assistant storage read failed");}
 }
 /** Tag expired immutable transcripts for S3 lifecycle. Pending lifecycle removal is normal. */
 public boolean expireAssistantVersions(String key) throws IOException {
  if(s3Client==null)throw new IOException("S3 unavailable");
  try {
   var list=s3Client.listObjectVersions(software.amazon.awssdk.services.s3.model.ListObjectVersionsRequest.builder()
     .bucket(bucket).prefix(key).maxKeys(1000).build());
   boolean versions=false;
   for(var version:list.versions())if(key.equals(version.key())) {
    versions=true;
    var tags=new java.util.ArrayList<>(s3Client.getObjectTagging(software.amazon.awssdk.services.s3.model.GetObjectTaggingRequest.builder()
      .bucket(bucket).key(key).versionId(version.versionId()).build()).tagSet());
    if(tags.stream().anyMatch(t->"watchtower-retention".equals(t.key())&&"expired".equals(t.value())))continue;
    tags.removeIf(t->"watchtower-retention".equals(t.key()));
    if(tags.size()>=10)throw new IOException("Transcript tag limit reached");
    tags.add(software.amazon.awssdk.services.s3.model.Tag.builder().key("watchtower-retention").value("expired").build());
    s3Client.putObjectTagging(software.amazon.awssdk.services.s3.model.PutObjectTaggingRequest.builder()
      .bucket(bucket).key(key).versionId(version.versionId()).tagging(software.amazon.awssdk.services.s3.model.Tagging.builder().tagSet(tags).build()).build());
   }
   // A HEAD 404 alone cannot prove that noncurrent versions have been removed.
   return !versions&&!Boolean.TRUE.equals(list.isTruncated())&&list.deleteMarkers().stream().noneMatch(m->key.equals(m.key()));
  } catch(SdkException e){throw new IOException("Assistant storage expiry failed",e);}
 }

}
