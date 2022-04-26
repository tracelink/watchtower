package com.tracelink.appsec.watchtower.core.scan.image.api.ecr;


import com.tracelink.appsec.watchtower.core.auth.model.ApiKeyEntity;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.RegisterState;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityFinding;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;
import com.tracelink.appsec.watchtower.core.scan.image.api.IImageApi;
import com.tracelink.appsec.watchtower.core.scan.image.entity.ImageViolationEntity;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudformation.CloudFormationAsyncClient;
import software.amazon.awssdk.services.cloudformation.model.CreateStackRequest;
import software.amazon.awssdk.services.cloudformation.model.CreateStackResponse;
import software.amazon.awssdk.services.cloudformation.model.DeleteStackRequest;
import software.amazon.awssdk.services.cloudformation.model.DeleteStackResponse;
import software.amazon.awssdk.services.cloudformation.model.OnFailure;
import software.amazon.awssdk.services.cloudformation.model.Parameter;
import software.amazon.awssdk.services.ecr.EcrClient;
import software.amazon.awssdk.services.ecr.model.Attribute;
import software.amazon.awssdk.services.ecr.model.BatchDeleteImageRequest;
import software.amazon.awssdk.services.ecr.model.BatchDeleteImageResponse;
import software.amazon.awssdk.services.ecr.model.DescribeImageScanFindingsRequest;
import software.amazon.awssdk.services.ecr.model.DescribeImageScanFindingsResponse;
import software.amazon.awssdk.services.ecr.model.FindingSeverity;
import software.amazon.awssdk.services.ecr.model.ImageIdentifier;
import software.amazon.awssdk.services.ecr.model.ImageScanFinding;
import software.amazon.awssdk.services.ecr.paginators.DescribeImageScanFindingsIterable;

/**
 * API to communicate with AWS ECR for image scans. Holds a reference to an {@link
 * EcrIntegrationEntity} to authenticate to ECR and CloudFormation in AWS.
 *
 * @author mcool
 */
public class EcrApi implements IImageApi {

	private static final Logger LOG = LoggerFactory.getLogger(EcrApi.class);
	private static final String STACK_TEMPLATE = "static/ecr-watchtower-webhook-template.json";
	private static final String STACK_NAME = "ecr-watchtower-webhook";

	private final EcrIntegrationEntity ecrIntegrationEntity;
	private final CloudFormationAsyncClient cfClient;
	private final EcrClient ecrClient;

	public EcrApi(EcrIntegrationEntity ecrIntegrationEntity) {
		this.ecrIntegrationEntity = ecrIntegrationEntity;
		Region region = Region.of(ecrIntegrationEntity.getRegion());
		StaticCredentialsProvider credentialsProvider = StaticCredentialsProvider.create(
				AwsBasicCredentials.create(ecrIntegrationEntity.getAwsAccessKey(),
						ecrIntegrationEntity.getAwsSecretKey()));
		this.cfClient = CloudFormationAsyncClient.builder().region(region)
				.credentialsProvider(credentialsProvider).build();
		this.ecrClient = EcrClient.builder().region(region)
				.credentialsProvider(credentialsProvider).build();
	}


	/**
	 * {@inheritDoc}
	 */
	@Override
	public void testClientConnection() throws ApiIntegrationException {
		// Check CloudFormation API access
		CompletableFuture<CreateStackResponse> createResponseFuture = cfClient
				.createStack(CreateStackRequest.builder().build());
		CompletableFuture<DeleteStackResponse> deleteResponseFuture = cfClient
				.deleteStack(DeleteStackRequest.builder().build());
		CreateStackResponse createStackResponse;
		DeleteStackResponse deleteStackResponse;
		try {
			createStackResponse = createResponseFuture.get();
			deleteStackResponse = deleteResponseFuture.get();
		} catch (InterruptedException | ExecutionException e) {
			throw new ApiIntegrationException(
					"Cannot test connection to CloudFormation: " + e.getMessage());
		}
		if (createStackResponse.sdkHttpResponse().statusCode() != 400) {
			throw new ApiIntegrationException("Cannot create stack via CloudFormation");
		}
		if (deleteStackResponse.sdkHttpResponse().statusCode() != 400) {
			throw new ApiIntegrationException("Cannot delete stack via CloudFormation");
		}

		// Check ECR API access
		DescribeImageScanFindingsResponse findingsResponse = ecrClient
				.describeImageScanFindings(DescribeImageScanFindingsRequest.builder().build());
		if (findingsResponse.sdkHttpResponse().statusCode() != 400) {
			throw new ApiIntegrationException("Cannot get scan findings via ECR");
		}
		BatchDeleteImageResponse deleteResponse = ecrClient
				.batchDeleteImage(BatchDeleteImageRequest.builder().build());
		if (deleteResponse.sdkHttpResponse().statusCode() != 400) {
			throw new ApiIntegrationException("Cannot delete images via ECR");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void register(Function<String, ApiKeyEntity> apiKeyFunction,
			Consumer<ApiIntegrationEntity> registerStateConsumer) {
		// Set register status to in progress
		ecrIntegrationEntity.setRegisterState(RegisterState.IN_PROGRESS);
		registerStateConsumer.accept(ecrIntegrationEntity);

		// Generate API key and secret for access to Watchtower
		ApiKeyEntity apiKeyEntity = apiKeyFunction.apply(ecrIntegrationEntity.getApiLabel());

		// Configure CloudFormation template parameters for request
		List<Parameter> templateParameters = new ArrayList<>();
		String watchtowerEndpoint = ServletUriComponentsBuilder.fromCurrentContextPath()
				.pathSegment("rest", "imagescan", ecrIntegrationEntity.getApiLabel()).build()
				.toString();
		templateParameters.add(Parameter.builder().parameterKey("WatchtowerEndpoint")
				.parameterValue(watchtowerEndpoint).build());
		templateParameters.add(Parameter.builder().parameterKey("WatchtowerApiKeyId")
				.parameterValue(apiKeyEntity.getApiKeyId()).build());
		templateParameters.add(Parameter.builder().parameterKey("WatchtowerSecret")
				.parameterValue(apiKeyEntity.getFirstTimeSecret()).build());

		// Configure action for async response
		BiConsumer<CreateStackResponse, Throwable> asyncAction = (createStackResponse, e) -> {
			if (createStackResponse != null) {
				ecrIntegrationEntity.setRegisterState(RegisterState.REGISTERED);
			} else {
				ecrIntegrationEntity.setRegisterState(RegisterState.FAILED);
				ecrIntegrationEntity.setRegisterError(e.getMessage());
			}
			registerStateConsumer.accept(ecrIntegrationEntity);
		};

		// Create CloudFormation stack
		try (InputStream is = getClass().getClassLoader().getResourceAsStream(STACK_TEMPLATE)) {
			String template = IOUtils.toString(is, StandardCharsets.UTF_8);
			CreateStackRequest request = CreateStackRequest.builder()
					.stackName(STACK_NAME)
					.templateBody(template)
					.parameters(templateParameters)
					.onFailure(OnFailure.DELETE).build();
			CompletableFuture<CreateStackResponse> response = cfClient.createStack(request);
			response.whenCompleteAsync(asyncAction);
		} catch (NullPointerException | IOException e) {
			LOG.warn("Cannot create CloudFormation stack for ECR integration with registry {}: {}",
					ecrIntegrationEntity.getRegistryId(), e.getMessage());
			ecrIntegrationEntity.setRegisterState(RegisterState.FAILED);
			ecrIntegrationEntity.setRegisterError(e.getMessage());
			registerStateConsumer.accept(ecrIntegrationEntity);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void unregister(Consumer<String> apiKeyConsumer,
			Consumer<ApiIntegrationEntity> registerStateConsumer) {
		// Set register status to unregistered and delete error if it is set
		ecrIntegrationEntity.setRegisterState(RegisterState.NOT_REGISTERED);
		ecrIntegrationEntity.setRegisterError(null);
		registerStateConsumer.accept(ecrIntegrationEntity);

		// Delete API key associated with this entity
		apiKeyConsumer.accept(ecrIntegrationEntity.getApiLabel());

		// Configure handler for async response
		BiConsumer<DeleteStackResponse, Throwable> asyncAction = (deleteStackResponse, e) -> {
			if (deleteStackResponse != null) {
				LOG.info("Deleted CloudFormation stack for ECR integration with registry {}",
						ecrIntegrationEntity.getRegistryId());
			} else {
				LOG.info(
						"Failed to delete CloudFormation stack for ECR integration with registry {}: {}",
						ecrIntegrationEntity.getRegistryId(), e.getMessage());
			}
		};

		// Delete CloudFormation stack
		DeleteStackRequest request = DeleteStackRequest.builder().stackName(STACK_NAME).build();
		CompletableFuture<DeleteStackResponse> response = cfClient.deleteStack(request);
		response.whenCompleteAsync(asyncAction);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void rejectImage(ImageScan image, List<ImageViolationEntity> violations) {
		BatchDeleteImageRequest request = BatchDeleteImageRequest.builder()
				.registryId(image.getApiLabel())
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
		List<ImageSecurityFinding> findings = responses.stream()
				.flatMap(response -> response.imageScanFindings().findings().stream())
				.map(this::createImageSecurityFinding)
				.collect(Collectors.toList());

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

}
