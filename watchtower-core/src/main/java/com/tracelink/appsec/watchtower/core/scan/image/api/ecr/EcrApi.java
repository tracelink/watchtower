package com.tracelink.appsec.watchtower.core.scan.image.api.ecr;


import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityFinding;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;
import com.tracelink.appsec.watchtower.core.scan.image.api.IImageApi;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.AwsResponse;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.waiters.WaiterResponse;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudformation.CloudFormationClient;
import software.amazon.awssdk.services.cloudformation.model.Capability;
import software.amazon.awssdk.services.cloudformation.model.CloudFormationException;
import software.amazon.awssdk.services.cloudformation.model.CreateStackRequest;
import software.amazon.awssdk.services.cloudformation.model.DeleteStackRequest;
import software.amazon.awssdk.services.cloudformation.model.DescribeStacksRequest;
import software.amazon.awssdk.services.cloudformation.model.DescribeStacksResponse;
import software.amazon.awssdk.services.cloudformation.model.OnFailure;
import software.amazon.awssdk.services.cloudformation.model.Parameter;
import software.amazon.awssdk.services.cloudformation.waiters.CloudFormationWaiter;
import software.amazon.awssdk.services.ecr.EcrClient;
import software.amazon.awssdk.services.ecr.model.*;
import software.amazon.awssdk.services.ecr.paginators.DescribeImageScanFindingsIterable;

/**
 * API to communicate with AWS ECR for image scans. Holds a reference to an
 * {@link EcrIntegrationEntity} to authenticate to ECR and CloudFormation in AWS.
 *
 * @author mcool
 */
public class EcrApi implements IImageApi {

	private static final Logger LOG = LoggerFactory.getLogger(EcrApi.class);
	private static final String STACK_NAME = "ecr-watchtower-webhook";
	private static final String TEST_CONNECTION_MSG = "Cannot %s via %s";

	private final EcrIntegrationEntity ecrIntegrationEntity;
	private final CloudFormationClient cfClient;
	private final EcrClient ecrClient;
	private final String watchtowerEndpoint;
	private final String STACK_TEMPLATE;

	public EcrApi(EcrIntegrationEntity ecrIntegrationEntity) {
		this.ecrIntegrationEntity = ecrIntegrationEntity;
		Region region = Region.of(ecrIntegrationEntity.getRegion());
		StaticCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(
				AwsBasicCredentials.create(ecrIntegrationEntity.getAwsAccessKey(),
						ecrIntegrationEntity.getAwsSecretKey()));
		this.cfClient = CloudFormationClient.builder().region(region)
				.credentialsProvider(credentialsProvider).build();
		this.ecrClient = EcrClient.builder().region(region)
				.credentialsProvider(credentialsProvider).build();
		this.watchtowerEndpoint = ServletUriComponentsBuilder.fromCurrentContextPath()
				.pathSegment("rest", "imagescan", ecrIntegrationEntity.getApiLabel()).build()
				.toString();
		// Determine if enhanced or basic scanning is configured in AWS
		// Assign STACK_TEMPLATE based on scan type
		GetRegistryScanningConfigurationRequest getRegistryScanningConfigurationRequest = GetRegistryScanningConfigurationRequest.builder().build();
		if (this.ecrClient.getRegistryScanningConfiguration(getRegistryScanningConfigurationRequest).scanningConfiguration().scanTypeAsString().equals("ENHANCED")) {
			this.STACK_TEMPLATE = "static/enhanced-ecr-watchtower-webhook-template.json";
		} else {
			this.STACK_TEMPLATE = "static/ecr-watchtower-webhook-template.json";
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void testClientConnection() throws ApiIntegrationException {
		// Check CloudFormation API access
		String createStackMessage = String
				.format(TEST_CONNECTION_MSG, "create stack", "CloudFormation");
		tryAwsRequest(() -> cfClient.createStack(CreateStackRequest.builder().build()),
				createStackMessage, 400);

		String describeStacksMessage = String
				.format(TEST_CONNECTION_MSG, "describe stacks", "CloudFormation");
		tryAwsRequest(() -> cfClient.describeStacks(DescribeStacksRequest.builder().build()),
				describeStacksMessage, 200);

		String deleteStackMessage = String
				.format(TEST_CONNECTION_MSG, "delete stack", "CloudFormation");
		tryAwsRequest(() -> cfClient.deleteStack(DeleteStackRequest.builder().build()),
				deleteStackMessage, 400);

		// Check ECR API access
		String findingsMessage = String.format(TEST_CONNECTION_MSG, "get scan findings", "ECR");
		tryAwsRequest(() -> ecrClient
				.describeImageScanFindings(DescribeImageScanFindingsRequest.builder().build()),
				findingsMessage, 400);

		String deleteImageMessage = String.format(TEST_CONNECTION_MSG, "delete image", "ECR");
		tryAwsRequest(() -> ecrClient.batchDeleteImage(BatchDeleteImageRequest.builder().build()),
				deleteImageMessage, 400);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void register(PasswordEncoder passwordEncoder) {
		// Generate secret for access to Watchtower
		String secretKey = UUID.randomUUID().toString();
		ecrIntegrationEntity.setWatchtowerSecret(passwordEncoder.encode(secretKey));

		// Configure CloudFormation template parameters for request
		List<Parameter> templateParameters = new ArrayList<>();
		templateParameters.add(Parameter.builder().parameterKey("WatchtowerEndpoint")
				.parameterValue(watchtowerEndpoint).build());
		templateParameters.add(Parameter.builder().parameterKey("WatchtowerApiKeyId")
				.parameterValue(ecrIntegrationEntity.getApiLabel()).build());
		templateParameters.add(Parameter.builder().parameterKey("WatchtowerSecret")
				.parameterValue(secretKey).build());

		// Create CloudFormation stack
		CreateStackRequest request;
		try (InputStream is = getClass().getClassLoader().getResourceAsStream(STACK_TEMPLATE)) {
			String template = IOUtils.toString(is, StandardCharsets.UTF_8);
			request = CreateStackRequest.builder()
					.stackName(STACK_NAME)
					.templateBody(template)
					.parameters(templateParameters)
					.capabilities(Capability.CAPABILITY_NAMED_IAM)
					.onFailure(OnFailure.DELETE).build();
		} catch (NullPointerException | IOException e) {
			LOG.warn("Cannot load CloudFormation template");
			return;
		}

		cfClient.createStack(request);
		CloudFormationWaiter waiter = cfClient.waiter();
		DescribeStacksRequest stacksRequest = DescribeStacksRequest.builder().stackName(STACK_NAME)
				.build();
		try {
			// This will only return a response in the event that the stack create is complete
			waiter.waitUntilStackCreateComplete(stacksRequest);
		} catch (SdkClientException e) {
			throw CloudFormationException.builder()
					.message("Create stack failed. See AWS for more details").cause(e).build();
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void unregister() {
		// Delete secret associated with this entity
		ecrIntegrationEntity.setWatchtowerSecret(null);

		// Delete CloudFormation stack
		DeleteStackRequest request = DeleteStackRequest.builder().stackName(STACK_NAME).build();
		cfClient.deleteStack(request);
		CloudFormationWaiter waiter = cfClient.waiter();
		DescribeStacksRequest stacksRequest = DescribeStacksRequest.builder().stackName(STACK_NAME)
				.build();
		WaiterResponse<DescribeStacksResponse> stacksResponse = waiter
				.waitUntilStackDeleteComplete(stacksRequest);

		stacksResponse.matched().exception().ifPresent(e -> {
			String message = e.getMessage();
			// Ignore exception if there is no stack to delete
			if (message.contains("Stack with id " + STACK_NAME + " does not exist")) {
				return;
			}
			throw CloudFormationException.builder().message(e.getMessage()).cause(e).build();
		});
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void rejectImage(ImageScan image, List<ImageViolationEntity> violations) {
		switch (ecrIntegrationEntity.getRejectOption()) {
			case DO_NOTHING:
				LOG.info("Skipping Image Rejection due to Integration Setting "
						+ ecrIntegrationEntity.getRejectOption().getName());
				break;
			case DELETE_IMAGE:
				deleteImage(image, violations);
				break;
			default:
				throw new IllegalArgumentException("Unknown Integration Entity rejection option");
		}
	}

	private void deleteImage(ImageScan image, List<ImageViolationEntity> violations) {
		BatchDeleteImageRequest request = BatchDeleteImageRequest.builder()
				.registryId(image.getRegistry())
				.repositoryName(image.getRepository())
				.imageIds(Collections
						.singleton(ImageIdentifier.builder().imageTag(image.getTag()).build()))
				.build();
		BatchDeleteImageResponse result = ecrClient.batchDeleteImage(request);
		if (result.failures().isEmpty()) {
			LOG.info("Deleted image with tag '{}' from repository '{}'", image.getTag(),
					image.getRepository());
		} else {
			result.failures().forEach(failure -> {
				LOG.warn("Failed to delete image with tag '{}' from repository '{}': {}",
						image.getTag(), image.getRepository(), failure.failureReason());
			});
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public ImageSecurityReport getSecurityReportForImage(ImageScan image) {
		DescribeImageScanFindingsRequest request = DescribeImageScanFindingsRequest.builder()
				.imageId(ImageIdentifier.builder().imageTag(image.getTag()).build())
				.registryId(image.getRegistry())
				.repositoryName(image.getRepository())
				.maxResults(1000)
				.build();

		// Iterate through all pages of findings
		DescribeImageScanFindingsIterable responses = ecrClient
				.describeImageScanFindingsPaginator(request);

		// Allow enhanced findings time to populate fully
		try {
			Thread.sleep(60000);
		} catch (Exception e) {
			LOG.warn("Pause before findings failed. Results may not be accurate.");
		}

		// Initialize findings
		List<ImageSecurityFinding> findings;

		// Check if enhanced scan findings exist, else iterate basic findings
		if (ecrClient.describeImageScanFindings(request).imageScanFindings().hasEnhancedFindings()) {
			findings = responses.stream()
					.flatMap(response -> response.imageScanFindings().enhancedFindings().stream())
					.map(this::createEnhancedImageSecurityFinding)
					.collect(Collectors.toList());
		} else {
			findings = responses.stream()
					.flatMap(response -> response.imageScanFindings().findings().stream())
					.map(this::createImageSecurityFinding)
					.collect(Collectors.toList());
		}

		ImageSecurityReport report = new ImageSecurityReport(image);
		report.setFindings(findings);
		return report;
	}

	private ImageSecurityFinding createImageSecurityFinding(ImageScanFinding imageScanFinding) {
		ImageSecurityFinding finding = new ImageSecurityFinding();
		finding.setSeverity(convertSeverityToRulePriority(imageScanFinding.severity()));
		Map<String, String> attributesMap = imageScanFinding.attributes().stream()
				.collect(Collectors.toMap(Attribute::key, Attribute::value));
		finding.setPackageName(attributesMap.getOrDefault("package_name", "N/A"));
		finding.setPackageVersion(
				attributesMap.getOrDefault("package_version", "N/A"));
		finding.setScore(attributesMap.getOrDefault("CVSS2_SCORE", "N/A"));
		finding.setVector(attributesMap.getOrDefault("CVSS2_VECTOR", "N/A"));
		finding.setFindingName(imageScanFinding.name());
		finding.setDescription(imageScanFinding.description());
		finding.setUri(imageScanFinding.uri());
		return finding;
	}

	private ImageSecurityFinding createEnhancedImageSecurityFinding(EnhancedImageScanFinding enhancedImageScanFinding) {
		ImageSecurityFinding finding = new ImageSecurityFinding();
		finding.setSeverity(convertSeverityToRulePriority(enhancedImageScanFinding.severity()));
		finding.setPackageName(enhancedImageScanFinding.packageVulnerabilityDetails().vulnerablePackages().get(0).name());
		finding.setPackageVersion(enhancedImageScanFinding.packageVulnerabilityDetails().vulnerablePackages().get(0).version());
		try {
			if (enhancedImageScanFinding.packageVulnerabilityDetails().cvss().get(0).version().equals("2.0")) {
				finding.setScore(enhancedImageScanFinding.packageVulnerabilityDetails().cvss().get(0).baseScore().toString());
				finding.setVector(enhancedImageScanFinding.packageVulnerabilityDetails().cvss().get(0).scoringVector());
			}
			else {
				finding.setScore("N/A");
				finding.setVector("N/A");
			}
		} catch (Exception e) {
			LOG.debug("@NotNull information missing from PackageVulnerabilityDetails().");
			finding.setScore("N/A");
			finding.setVector("N/A");
		}

		finding.setFindingName(enhancedImageScanFinding.title());
		finding.setDescription(enhancedImageScanFinding.description());
		finding.setUri(enhancedImageScanFinding.packageVulnerabilityDetails().sourceUrl());
		return finding;
	}

	private RulePriority convertSeverityToRulePriority(FindingSeverity severity) {
		switch (severity) {
			case CRITICAL:
			case HIGH:
				return RulePriority.HIGH;
			case MEDIUM:
				return RulePriority.MEDIUM;
			case LOW:
			case INFORMATIONAL:
			case UNDEFINED:
			case UNKNOWN_TO_SDK_VERSION:
			default:
				return RulePriority.LOW;
		}
	}

	private RulePriority convertSeverityToRulePriority(String severity) {
		switch (severity) {
			case "CRITICAL":
			case "HIGH":
				return RulePriority.HIGH;
			case "MEDIUM":
				return RulePriority.MEDIUM;
			case "LOW":
			case "INFORMATIONAL":
			case "UNDEFINED":
			case "UNKNOWN_TO_SDK_VERSION":
			default:
				return RulePriority.LOW;
		}
	}

	/**
	 * Helper to wrap AWS requests in a try/catch to handle expected errors. Uses the given message
	 * for any thrown exception.
	 *
	 * @param request supplier for the request to execute
	 * @param message message to include with the thrown exception
	 * @param <T>     type of the AWS response
	 * @throws ApiIntegrationException if the AWS request cannot be made without unexpected errors
	 */
	private <T extends AwsResponse> void tryAwsRequest(Supplier<T> request, String message,
			int validStatusCode) throws ApiIntegrationException {
		T response;
		try {
			response = request.get();
		} catch (CloudFormationException | EcrException e) {
			if (e.statusCode() != validStatusCode) {
				throw new ApiIntegrationException(message + ": " + e.getMessage());
			}
			return;
		} catch (Exception e) {
			throw new ApiIntegrationException(message + ": " + e.getMessage());
		}
		if (response.sdkHttpResponse().statusCode() != validStatusCode) {
			throw new ApiIntegrationException(
					message + ": Received status code " + response.sdkHttpResponse().statusCode());
		}
	}

}
