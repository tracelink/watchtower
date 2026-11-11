package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.tracelink.appsec.watchtower.core.scan.storage.S3Service;

/**
 * Keeps repository scan reports in S3 when a bucket is configured, otherwise in a local
 * directory. A multi-pod deployment without S3 refuses to start, since one pod could not read
 * another's reports.
 *
 * @author Watchtower
 */
@Configuration
public class RepoReportStoreConfiguration {

	private static final Logger LOG = LoggerFactory.getLogger(RepoReportStoreConfiguration.class);

	@Bean
	public RepoReportStore repoReportStore(S3Service s3Service,
			@Value("${watchtower.reposcan.report-dir:./reports}") String reportDir,
			@Value("${watchtower.cluster.multi-pod:false}") boolean multiPod) {
		if (s3Service.isEnabled()) {
			return new S3RepoReportStore(s3Service);
		}
		if (multiPod) {
			throw new IllegalStateException("watchtower.cluster.multi-pod is set but no S3"
					+ " bucket is: repository scan reports must be shared by every pod");
		}
		LOG.info("No S3 bucket configured; repository scan reports are kept in {}", reportDir);
		return new LocalRepoReportStore(Path.of(reportDir));
	}
}
