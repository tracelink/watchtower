package com.tracelink.appsec.module.awssecurity;

import java.time.Duration;
import java.util.*;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.retries.StandardRetryStrategy;
import software.amazon.awssdk.services.securityagent.SecurityAgentClient;
import software.amazon.awssdk.services.securityagent.model.*;
import com.tracelink.appsec.module.awssecurity.AwsSecuritySettings.Profile;

/** Actual BOM 2.46.21 contract. Never log SDK requests/responses: they can contain source. */
@Component
public class AwsSecurityClientGateway implements AutoCloseable {
    private final SecurityAgentClient reads;
    private final SecurityAgentClient mutations;
    @org.springframework.beans.factory.annotation.Autowired
    public AwsSecurityClientGateway(AwsSecuritySettings settings) {
        this(client(settings.region(), 3), client(settings.region(), 1));
    }
    public AwsSecurityClientGateway(SecurityAgentClient reads, SecurityAgentClient mutations) {
        this.reads = reads; this.mutations = mutations;
    }
    private static SecurityAgentClient client(String region, int attempts) {
        return SecurityAgentClient.builder().region(Region.of(region.isBlank() ? "us-east-1" : region))
            .credentialsProvider(DefaultCredentialsProvider.builder().build())
            .httpClientBuilder(ApacheHttpClient.builder().connectionTimeout(Duration.ofSeconds(5))
                .connectionAcquisitionTimeout(Duration.ofSeconds(5)).socketTimeout(Duration.ofSeconds(30)).maxConnections(8))
            .overrideConfiguration(c -> c.apiCallTimeout(Duration.ofSeconds(60)).apiCallAttemptTimeout(Duration.ofSeconds(35))
                .retryStrategy(StandardRetryStrategy.builder().maxAttempts(attempts).build())).build();
    }
    public AgentSpace readiness(Profile p) {
        return reads.batchGetAgentSpaces(BatchGetAgentSpacesRequest.builder().agentSpaceIds(p.spaceId()).build())
                .agentSpaces().stream().filter(s -> p.spaceId().equals(s.agentSpaceId())).findFirst()
                .orElseThrow(() -> new IllegalStateException("Agent Space unavailable"));
    }
    public String create(Profile p, String correlation, String sourceUri) {
        var request = CreateCodeReviewRequest.builder().agentSpaceId(p.spaceId()).title(correlation)
            .assets(Assets.builder().sourceCode(SourceCodeRepository.builder().s3Location(sourceUri).build()).build())
            .serviceRole(p.serviceRole())
            .validationMode(ValidationMode.DISABLED).codeRemediationStrategy(CodeRemediationStrategy.DISABLED);
        if (!p.logGroup().isBlank()) request.logConfig(CloudWatchLog.builder().logGroup(p.logGroup()).build());
        return mutations.createCodeReview(request.build()).codeReviewId();
    }
    /**
     * Points an existing (shared) review at another scan's source. AWS refuses a source update that does not repeat the service
     * role, so every setting a create sends is sent again; that also heals a review made under an older profile.
     */
    public void updateSource(Profile p, String review, String sourceUri) {
        var request = UpdateCodeReviewRequest.builder().agentSpaceId(p.spaceId()).codeReviewId(review)
            .assets(Assets.builder().sourceCode(SourceCodeRepository.builder().s3Location(sourceUri).build()).build())
            .serviceRole(p.serviceRole())
            .validationMode(ValidationMode.DISABLED).codeRemediationStrategy(CodeRemediationStrategy.DISABLED);
        if (!p.logGroup().isBlank()) request.logConfig(CloudWatchLog.builder().logGroup(p.logGroup()).build());
        mutations.updateCodeReview(request.build());
    }
    /** The repository's shared review, found by its title alone (its source changes with every scan); two matches are never chosen between. */
    public Optional<String> findReviewByTitle(Profile p, String title) {
        List<String> candidates = new ArrayList<>(); Set<String> tokens = new HashSet<>(); String token = null;
        do {
            var page = reads.listCodeReviews(ListCodeReviewsRequest.builder().agentSpaceId(p.spaceId()).nextToken(token).build());
            for (var summary : page.codeReviewSummaries()) {
                if (!title.equals(summary.title())) continue;
                var full = reads.batchGetCodeReviews(BatchGetCodeReviewsRequest.builder().agentSpaceId(p.spaceId())
                    .codeReviewIds(summary.codeReviewId()).build());
                for (var review : full.codeReviews())
                    if (p.spaceId().equals(review.agentSpaceId()) && title.equals(review.title()) && p.serviceRole().equals(review.serviceRole())
                        && review.assets() != null && review.assets().integratedRepositories().isEmpty()) candidates.add(review.codeReviewId());
            }
            token = page.nextToken(); checkToken(token, tokens);
        } while (token != null && !token.isBlank());
        return candidates.size() == 1 ? Optional.of(candidates.getFirst()) : Optional.empty();
    }
    /**
     * A job records the source it was started with, and every scan's source address is unique to it, so the job a lost start call
     * created is the one whose recorded source is ours. Only jobs created after the start was attempted can be it.
     */
    public Optional<String> findJobBySource(Profile p, String review, String sourceUri, java.time.Instant notBefore) {
        List<String> recent = new ArrayList<>(); Set<String> tokens = new HashSet<>(); String token = null;
        do {
            var page = reads.listCodeReviewJobsForCodeReview(ListCodeReviewJobsForCodeReviewRequest.builder()
                .agentSpaceId(p.spaceId()).codeReviewId(review).nextToken(token).build());
            for (var job : page.codeReviewJobSummaries()) if (job.createdAt() != null && !job.createdAt().isBefore(notBefore)) recent.add(job.codeReviewJobId());
            token = page.nextToken(); checkToken(token, tokens);
        } while (token != null && !token.isBlank());
        List<String> matches = new ArrayList<>();
        for (int from = 0; from < recent.size(); from += 10) {
            var batch = recent.subList(from, Math.min(recent.size(), from + 10));
            for (var job : reads.batchGetCodeReviewJobs(BatchGetCodeReviewJobsRequest.builder().agentSpaceId(p.spaceId()).codeReviewJobIds(batch).build()).codeReviewJobs())
                if (review.equals(job.codeReviewId()) && job.hasSourceCode() && job.sourceCode().stream().anyMatch(s -> sourceUri.equals(s.s3Location())))
                    matches.add(job.codeReviewJobId());
        }
        return matches.size() == 1 ? Optional.of(matches.getFirst()) : Optional.empty();
    }
    public String start(Profile p, String review, String diffUri) {
        var request = StartCodeReviewJobRequest.builder().agentSpaceId(p.spaceId()).codeReviewId(review);
        if (diffUri != null) request.diffSource(DiffSource.builder().s3Uri(diffUri).build());
        return mutations.startCodeReviewJob(request.build()).codeReviewJobId();
    }
    public CodeReviewJob job(Profile p, String review, String job) {
        return reads.batchGetCodeReviewJobs(BatchGetCodeReviewJobsRequest.builder().agentSpaceId(p.spaceId())
            .codeReviewJobIds(job).build()).codeReviewJobs().stream()
            .filter(j -> job.equals(j.codeReviewJobId()) && review.equals(j.codeReviewId())).findFirst()
            .orElseThrow(() -> new IllegalStateException("Job unavailable or association mismatch"));
    }
    public void stop(Profile p, String job) {
        mutations.stopCodeReviewJob(StopCodeReviewJobRequest.builder().agentSpaceId(p.spaceId()).codeReviewJobId(job).build());
    }
    public ListFindingsResponse list(Profile p, String job, String token) {
        return reads.listFindings(ListFindingsRequest.builder().agentSpaceId(p.spaceId()).codeReviewJobId(job)
            .maxResults(100).nextToken(token).build());
    }
    public BatchGetFindingsResponse details(Profile p, List<String> ids) {
        return reads.batchGetFindings(BatchGetFindingsRequest.builder().agentSpaceId(p.spaceId()).findingIds(ids).build());
    }
    public Optional<String> reconcileCreate(Profile p, String correlation, String sourceUri) {
        List<String> candidates = new ArrayList<>(); Set<String> tokens = new HashSet<>(); String token = null;
        do {
            var page = reads.listCodeReviews(ListCodeReviewsRequest.builder().agentSpaceId(p.spaceId()).nextToken(token).build());
            for (var summary : page.codeReviewSummaries()) {
                if (!correlation.equals(summary.title())) continue;
                var full = reads.batchGetCodeReviews(BatchGetCodeReviewsRequest.builder().agentSpaceId(p.spaceId())
                    .codeReviewIds(summary.codeReviewId()).build());
                for (var review : full.codeReviews()) {
                    if (p.spaceId().equals(review.agentSpaceId()) && correlation.equals(review.title())
                        && p.serviceRole().equals(review.serviceRole()) && review.assets() != null
                        && review.assets().sourceCode().size() == 1 && review.assets().integratedRepositories().isEmpty()
                        && sourceUri.equals(review.assets().sourceCode().getFirst().s3Location())
                        && review.validationMode() == ValidationMode.DISABLED && review.codeRemediationStrategy() == CodeRemediationStrategy.DISABLED
                        && (p.logGroup().isBlank() || (review.logConfig() != null && p.logGroup().equals(review.logConfig().logGroup())))) candidates.add(review.codeReviewId());
                }
            }
            token = page.nextToken(); checkToken(token, tokens);
        } while (token != null && !token.isBlank());
        return candidates.size() == 1 ? Optional.of(candidates.getFirst()) : Optional.empty();
    }
    public Optional<String> reconcileStart(Profile p, String review) {
        Set<String> jobs = new HashSet<>(), tokens = new HashSet<>(); String token = null;
        do {
            var page = reads.listCodeReviewJobsForCodeReview(ListCodeReviewJobsForCodeReviewRequest.builder()
                .agentSpaceId(p.spaceId()).codeReviewId(review).nextToken(token).build());
            page.codeReviewJobSummaries().forEach(j -> jobs.add(j.codeReviewJobId()));
            token = page.nextToken(); checkToken(token, tokens);
        } while (token != null && !token.isBlank());
        return jobs.size() == 1 ? Optional.of(jobs.iterator().next()) : Optional.empty();
    }
    static void checkToken(String token, Set<String> tokens) {
        if (token != null && !token.isBlank() && (!tokens.add(token) || tokens.size() > 10000))
            throw new IllegalStateException("Provider pagination did not terminate");
    }
    public boolean retire(Profile p, String review) {
        return mutations.batchDeleteCodeReviews(BatchDeleteCodeReviewsRequest.builder().agentSpaceId(p.spaceId())
                .codeReviewIds(review).build()).deleted().contains(review);
    }
    public void close() { reads.close(); if (mutations != reads) mutations.close(); }
}
