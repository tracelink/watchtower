package com.tracelink.appsec.watchtower.core.scan.image.api.ecr;

import java.util.Arrays;
import java.util.Collections;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import com.tracelink.appsec.watchtower.core.logging.CoreLogWatchExtension;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationException;
import com.tracelink.appsec.watchtower.core.scan.image.ImageScan;
import com.tracelink.appsec.watchtower.core.scan.image.ImageSecurityReport;

import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.http.SdkHttpResponse;
import software.amazon.awssdk.services.cloudformation.CloudFormationClient;
import software.amazon.awssdk.services.cloudformation.model.CloudFormationException;
import software.amazon.awssdk.services.cloudformation.model.CreateStackRequest;
import software.amazon.awssdk.services.cloudformation.model.CreateStackResponse;
import software.amazon.awssdk.services.cloudformation.model.DeleteStackRequest;
import software.amazon.awssdk.services.cloudformation.model.DeleteStackResponse;
import software.amazon.awssdk.services.cloudformation.model.DescribeStacksRequest;
import software.amazon.awssdk.services.cloudformation.model.DescribeStacksResponse;
import software.amazon.awssdk.services.cloudformation.model.Stack;
import software.amazon.awssdk.services.cloudformation.waiters.CloudFormationWaiter;
import software.amazon.awssdk.services.ecr.EcrClient;
import software.amazon.awssdk.services.ecr.model.Attribute;
import software.amazon.awssdk.services.ecr.model.BatchDeleteImageRequest;
import software.amazon.awssdk.services.ecr.model.BatchDeleteImageResponse;
import software.amazon.awssdk.services.ecr.model.DescribeImageScanFindingsRequest;
import software.amazon.awssdk.services.ecr.model.DescribeImageScanFindingsResponse;
import software.amazon.awssdk.services.ecr.model.FindingSeverity;
import software.amazon.awssdk.services.ecr.model.ImageFailure;
import software.amazon.awssdk.services.ecr.model.ImageScanFinding;
import software.amazon.awssdk.services.ecr.model.ImageScanFindings;
import software.amazon.awssdk.services.ecr.paginators.DescribeImageScanFindingsIterable;

@ExtendWith(SpringExtension.class)
public class EcrApiTest {

	@RegisterExtension
	public CoreLogWatchExtension logWatcher = CoreLogWatchExtension.forClass(EcrApi.class);

	private EcrIntegrationEntity ecrIntegrationEntity;
	private PasswordEncoder passwordEncoder;

	@BeforeEach
	public void setup() {
		ecrIntegrationEntity = new EcrIntegrationEntity();
		ecrIntegrationEntity.setApiLabel("ecrIntegration");
		ecrIntegrationEntity.setRegion("us-east-1");
		ecrIntegrationEntity.setRegistryId("1234567890");
		ecrIntegrationEntity.setAwsAccessKey("foo");
		ecrIntegrationEntity.setAwsSecretKey("bar");
		ecrIntegrationEntity.setRejectOption(EcrRejectOption.DELETE_IMAGE);

		MockHttpServletRequest request = new MockHttpServletRequest();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

		passwordEncoder = BDDMockito.mock(PasswordEncoder.class);
		BDDMockito.when(passwordEncoder.encode(BDDMockito.anyString()))
				.thenAnswer(i -> i.getArguments()[0]);
	}

	/////
	// Test Client Connection
	/////
	@Test
	public void testClientConnectionFailCreateStack() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		ReflectionTestUtils
				.setField(ecrApi, "cfClient",
						getMockCloudFormationClient(403, 400, 200, false, "CREATE_COMPLETE"));

		try {
			ecrApi.testClientConnection();
			MatcherAssert.assertThat("Exception should have been thrown", false);
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.is(
					"Cannot create stack via CloudFormation: Received status code 403"));
		}
	}

	@Test
	public void testClientConnectionFailDeleteStack() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		ReflectionTestUtils
				.setField(ecrApi, "cfClient",
						getMockCloudFormationClient(400, 403, 200, false, "CREATE_COMPLETE"));

		try {
			ecrApi.testClientConnection();
			MatcherAssert.assertThat("Exception should have been thrown", false);
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.is(
					"Cannot delete stack via CloudFormation: Received status code 403"));
		}
	}

	@Test
	public void testClientConnectionFailDescribeStacks() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		ReflectionTestUtils
				.setField(ecrApi, "cfClient",
						getMockCloudFormationClient(400, 400, 403, false, "CREATE_COMPLETE"));

		try {
			ecrApi.testClientConnection();
			MatcherAssert.assertThat("Exception should have been thrown", false);
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.is(
					"Cannot describe stacks via CloudFormation: Received status code 403"));
		}
	}

	@Test
	public void testClientConnectionExceptionDescribeStacks() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		ReflectionTestUtils
				.setField(ecrApi, "cfClient",
						getMockCloudFormationClient(400, 400, 403, true, "Error occurred"));

		try {
			ecrApi.testClientConnection();
			MatcherAssert.assertThat("Exception should have been thrown", false);
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.startsWith(
					"Cannot describe stacks via CloudFormation: Error occurred"));
		}
	}

	@Test
	public void testClientConnectionFailDescribeFindings() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		ReflectionTestUtils
				.setField(ecrApi, "cfClient",
						getMockCloudFormationClient(400, 400, 200, true, "This is ok"));
		ReflectionTestUtils
				.setField(ecrApi, "ecrClient", getMockEcrClient(403, true, 400, false));

		try {
			ecrApi.testClientConnection();
			MatcherAssert.assertThat("Exception should have been thrown", false);
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.is(
					"Cannot get scan findings via ECR: Received status code 403"));
		}
	}

	@Test
	public void testClientConnectionFailDeleteImage() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		ReflectionTestUtils
				.setField(ecrApi, "cfClient",
						getMockCloudFormationClient(400, 400, 200, false, "CREATE_COMPLETE"));
		ReflectionTestUtils
				.setField(ecrApi, "ecrClient", getMockEcrClient(400, true, 403, false));

		try {
			ecrApi.testClientConnection();
			MatcherAssert.assertThat("Exception should have been thrown", false);
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat(e.getMessage(), Matchers.is(
					"Cannot delete image via ECR: Received status code 403"));
		}
	}

	@Test
	public void testClientConnectionSucceed() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		ReflectionTestUtils
				.setField(ecrApi, "cfClient",
						getMockCloudFormationClient(400, 400, 200, false, "CREATE_COMPLETE"));
		ReflectionTestUtils
				.setField(ecrApi, "ecrClient", getMockEcrClient(400, true, 400, false));

		try {
			ecrApi.testClientConnection();
		} catch (ApiIntegrationException e) {
			MatcherAssert.assertThat("Exception should not have been thrown", false);
		}
	}

	/////
	// Register
	/////
	@Test
	public void testRegister() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		CloudFormationClient cfClient = getMockCloudFormationClient(200, 400, 200, false,
				"CREATE_COMPLETE");
		ReflectionTestUtils.setField(ecrApi, "cfClient", cfClient);

		ecrApi.register(passwordEncoder);
		BDDMockito.verify(passwordEncoder).encode(BDDMockito.any());
		MatcherAssert
				.assertThat(ecrIntegrationEntity.getWatchtowerSecret(), Matchers.notNullValue());
		ArgumentCaptor<CreateStackRequest> createStackRequest = ArgumentCaptor
				.forClass(CreateStackRequest.class);
		BDDMockito.verify(cfClient).createStack(createStackRequest.capture());
		MatcherAssert.assertThat(createStackRequest.getValue().stackName(),
				Matchers.is("ecr-watchtower-webhook"));
		BDDMockito.verify(cfClient).describeStacks(BDDMockito.any(DescribeStacksRequest.class));
	}

	@Test
	public void testRegisterException() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		CloudFormationClient cfClient = getMockCloudFormationClient(200, 400, 400, true,
				"CREATE_FAILED");
		ReflectionTestUtils.setField(ecrApi, "cfClient", cfClient);

		try {
			ecrApi.register(passwordEncoder);
			MatcherAssert.assertThat("Exception should have been thrown", false);
		} catch (CloudFormationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.is("Create stack failed. See AWS for more details"));
		}

		BDDMockito.verify(passwordEncoder).encode(BDDMockito.any());
		MatcherAssert
				.assertThat(ecrIntegrationEntity.getWatchtowerSecret(), Matchers.notNullValue());
		ArgumentCaptor<CreateStackRequest> createStackRequest = ArgumentCaptor
				.forClass(CreateStackRequest.class);
		BDDMockito.verify(cfClient).createStack(createStackRequest.capture());
		MatcherAssert.assertThat(createStackRequest.getValue().stackName(),
				Matchers.is("ecr-watchtower-webhook"));
		BDDMockito.verify(cfClient).describeStacks(BDDMockito.any(DescribeStacksRequest.class));
	}

	/////
	// Unregister
	/////
	@Test
	public void testUnregister() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		CloudFormationClient cfClient = getMockCloudFormationClient(200, 200, 200, false,
				"DELETE_COMPLETE");
		ReflectionTestUtils.setField(ecrApi, "cfClient", cfClient);

		ecrApi.unregister();
		MatcherAssert.assertThat(ecrIntegrationEntity.getWatchtowerSecret(), Matchers.nullValue());
		ArgumentCaptor<DeleteStackRequest> deleteStackRequest = ArgumentCaptor
				.forClass(DeleteStackRequest.class);
		BDDMockito.verify(cfClient).deleteStack(deleteStackRequest.capture());
		MatcherAssert.assertThat(deleteStackRequest.getValue().stackName(),
				Matchers.is("ecr-watchtower-webhook"));
		BDDMockito.verify(cfClient).describeStacks(BDDMockito.any(DescribeStacksRequest.class));
	}

	@Test
	public void testUnregisterExceptionNoStack() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		CloudFormationClient cfClient = getMockCloudFormationClient(200, 400, 400, true,
				"Stack with id ecr-watchtower-webhook does not exist");
		ReflectionTestUtils.setField(ecrApi, "cfClient", cfClient);

		ecrApi.unregister();

		MatcherAssert.assertThat(ecrIntegrationEntity.getWatchtowerSecret(), Matchers.nullValue());
		ArgumentCaptor<DeleteStackRequest> deleteStackRequest = ArgumentCaptor
				.forClass(DeleteStackRequest.class);
		BDDMockito.verify(cfClient).deleteStack(deleteStackRequest.capture());
		MatcherAssert.assertThat(deleteStackRequest.getValue().stackName(),
				Matchers.is("ecr-watchtower-webhook"));
		BDDMockito.verify(cfClient).describeStacks(BDDMockito.any(DescribeStacksRequest.class));
	}

	@Test
	public void testUnregisterException() {
		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		CloudFormationClient cfClient = getMockCloudFormationClient(200, 400, 400, true,
				"DELETE_FAILED");
		ReflectionTestUtils.setField(ecrApi, "cfClient", cfClient);

		try {
			ecrApi.unregister();
			MatcherAssert.assertThat("Exception should have been thrown", false);
		} catch (CloudFormationException e) {
			MatcherAssert.assertThat(e.getMessage(),
					Matchers.startsWith("DELETE_FAILED"));
		}

		MatcherAssert.assertThat(ecrIntegrationEntity.getWatchtowerSecret(), Matchers.nullValue());
		ArgumentCaptor<DeleteStackRequest> deleteStackRequest = ArgumentCaptor
				.forClass(DeleteStackRequest.class);
		BDDMockito.verify(cfClient).deleteStack(deleteStackRequest.capture());
		MatcherAssert.assertThat(deleteStackRequest.getValue().stackName(),
				Matchers.is("ecr-watchtower-webhook"));
		BDDMockito.verify(cfClient).describeStacks(BDDMockito.any(DescribeStacksRequest.class));
	}

	/////
	// Unregister
	/////

	@Test
	public void testRejectImage() {
		ImageScan imageScan = new EcrImageScan(ecrIntegrationEntity.getApiLabel());
		imageScan.setRegistry("1234567890");
		imageScan.setRepository("myImage");
		imageScan.setTag("latest");

		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		EcrClient ecrClient = getMockEcrClient(400, true, 200, false);
		ReflectionTestUtils.setField(ecrApi, "ecrClient", ecrClient);

		ecrApi.rejectImage(imageScan, Collections.emptyList());

		ArgumentCaptor<BatchDeleteImageRequest> deleteImageRequest = ArgumentCaptor
				.forClass(BatchDeleteImageRequest.class);
		BDDMockito.verify(ecrClient).batchDeleteImage(deleteImageRequest.capture());
		MatcherAssert
				.assertThat(deleteImageRequest.getValue().registryId(), Matchers.is("1234567890"));
		MatcherAssert
				.assertThat(deleteImageRequest.getValue().repositoryName(), Matchers.is("myImage"));
		MatcherAssert.assertThat(deleteImageRequest.getValue().imageIds().get(0).toString(),
				Matchers.is("ImageIdentifier(ImageTag=latest)"));

		MatcherAssert.assertThat(logWatcher.getMessages().size(), Matchers.is(1));
		MatcherAssert.assertThat(logWatcher.getFormattedMessages().get(0),
				Matchers.is("Deleted image with tag 'latest' from repository 'myImage'"));
	}

	@Test
	public void testRejectImageDoNothing() {
		ecrIntegrationEntity.setRejectOption(EcrRejectOption.DO_NOTHING);
		ImageScan imageScan = new EcrImageScan(ecrIntegrationEntity.getApiLabel());
		imageScan.setRegistry("1234567890");
		imageScan.setRepository("myImage");
		imageScan.setTag("latest");

		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		EcrClient ecrClient = getMockEcrClient(400, true, 200, false);
		ReflectionTestUtils.setField(ecrApi, "ecrClient", ecrClient);

		ecrApi.rejectImage(imageScan, Collections.emptyList());

		BDDMockito.verify(ecrClient, BDDMockito.never())
				.batchDeleteImage(BDDMockito.any(BatchDeleteImageRequest.class));
		MatcherAssert.assertThat(logWatcher.getMessages().size(), Matchers.is(1));
		MatcherAssert.assertThat(logWatcher.getFormattedMessages().get(0),
				Matchers.containsString("Skipping Image Rejection"));
	}

	@Test
	public void testRejectImageFailures() {
		ImageScan imageScan = new EcrImageScan(ecrIntegrationEntity.getApiLabel());
		imageScan.setRegistry("1234567890");
		imageScan.setRepository("myImage");
		imageScan.setTag("latest");

		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		EcrClient ecrClient = getMockEcrClient(400, true, 400, true);
		ReflectionTestUtils.setField(ecrApi, "ecrClient", ecrClient);

		ecrApi.rejectImage(imageScan, Collections.emptyList());

		ArgumentCaptor<BatchDeleteImageRequest> deleteImageRequest = ArgumentCaptor
				.forClass(BatchDeleteImageRequest.class);
		BDDMockito.verify(ecrClient).batchDeleteImage(deleteImageRequest.capture());
		MatcherAssert
				.assertThat(deleteImageRequest.getValue().registryId(), Matchers.is("1234567890"));
		MatcherAssert
				.assertThat(deleteImageRequest.getValue().repositoryName(), Matchers.is("myImage"));
		MatcherAssert.assertThat(deleteImageRequest.getValue().imageIds().get(0).toString(),
				Matchers.is("ImageIdentifier(ImageTag=latest)"));

		MatcherAssert.assertThat(logWatcher.getMessages().size(), Matchers.is(1));
		MatcherAssert.assertThat(logWatcher.getFormattedMessages().get(0),
				Matchers.is(
						"Failed to delete image with tag 'latest' from repository 'myImage': Cannot delete image"));
	}

	/////
	// Get Security Report
	/////

	@Test
	public void testGetSecurityReportForImage() {
		ImageScan imageScan = new EcrImageScan(ecrIntegrationEntity.getApiLabel());
		imageScan.setRegistry("1234567890");
		imageScan.setRepository("myImage");
		imageScan.setTag("latest");

		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		EcrClient ecrClient = getMockEcrClient(200, false, 400, false);
		ReflectionTestUtils.setField(ecrApi, "ecrClient", ecrClient);

		ImageSecurityReport report = ecrApi.getSecurityReportForImage(imageScan);

		ArgumentCaptor<DescribeImageScanFindingsRequest> describeFindingsRequest = ArgumentCaptor
				.forClass(DescribeImageScanFindingsRequest.class);
		BDDMockito.verify(ecrClient)
				.describeImageScanFindingsPaginator(describeFindingsRequest.capture());
		MatcherAssert
				.assertThat(describeFindingsRequest.getValue().registryId(),
						Matchers.is("1234567890"));
		MatcherAssert
				.assertThat(describeFindingsRequest.getValue().repositoryName(),
						Matchers.is("myImage"));
		MatcherAssert.assertThat(describeFindingsRequest.getValue().imageId().toString(),
				Matchers.is("ImageIdentifier(ImageTag=latest)"));

		MatcherAssert.assertThat(report.getFindings().size(), Matchers.is(1));
		MatcherAssert.assertThat(report.getFindings().get(0).getFindingName(),
				Matchers.is("findingName"));
		MatcherAssert.assertThat(report.getFindings().get(0).getDescription(),
				Matchers.is("findingDescription"));
		MatcherAssert.assertThat(report.getFindings().get(0).getSeverity(), Matchers.is(
				RulePriority.LOW));
		MatcherAssert.assertThat(report.getFindings().get(0).getPackageName(), Matchers.is("a"));
		MatcherAssert.assertThat(report.getFindings().get(0).getPackageVersion(), Matchers.is("a"));
		MatcherAssert.assertThat(report.getFindings().get(0).getScore(), Matchers.is("a"));
		MatcherAssert.assertThat(report.getFindings().get(0).getVector(), Matchers.is("a"));
		MatcherAssert.assertThat(report.getFindings().get(0).getUri(),
				Matchers.is("https://example.com"));
	}

	@Test
	public void testGetSecurityReportForImageDefaultAttributes() {
		ImageScan imageScan = new EcrImageScan(ecrIntegrationEntity.getApiLabel());
		imageScan.setRegistry("1234567890");
		imageScan.setRepository("myImage");
		imageScan.setTag("latest");

		EcrApi ecrApi = ecrIntegrationEntity.createApi();
		EcrClient ecrClient = getMockEcrClient(200, true, 400, false);
		ReflectionTestUtils.setField(ecrApi, "ecrClient", ecrClient);

		ImageSecurityReport report = ecrApi.getSecurityReportForImage(imageScan);

		ArgumentCaptor<DescribeImageScanFindingsRequest> describeFindingsRequest = ArgumentCaptor
				.forClass(DescribeImageScanFindingsRequest.class);
		BDDMockito.verify(ecrClient)
				.describeImageScanFindingsPaginator(describeFindingsRequest.capture());
		MatcherAssert
				.assertThat(describeFindingsRequest.getValue().registryId(),
						Matchers.is("1234567890"));
		MatcherAssert
				.assertThat(describeFindingsRequest.getValue().repositoryName(),
						Matchers.is("myImage"));
		MatcherAssert.assertThat(describeFindingsRequest.getValue().imageId().toString(),
				Matchers.is("ImageIdentifier(ImageTag=latest)"));

		MatcherAssert.assertThat(report.getFindings().size(), Matchers.is(1));
		MatcherAssert.assertThat(report.getFindings().get(0).getFindingName(),
				Matchers.is("findingName"));
		MatcherAssert.assertThat(report.getFindings().get(0).getDescription(),
				Matchers.is("findingDescription"));
		MatcherAssert.assertThat(report.getFindings().get(0).getSeverity(), Matchers.is(
				RulePriority.HIGH));
		MatcherAssert.assertThat(report.getFindings().get(0).getPackageName(), Matchers.is("N/A"));
		MatcherAssert
				.assertThat(report.getFindings().get(0).getPackageVersion(), Matchers.is("N/A"));
		MatcherAssert.assertThat(report.getFindings().get(0).getScore(), Matchers.is("N/A"));
		MatcherAssert.assertThat(report.getFindings().get(0).getVector(), Matchers.is("N/A"));
		MatcherAssert.assertThat(report.getFindings().get(0).getUri(),
				Matchers.is("https://example.com"));
	}

	/////
	// Mocks
	/////

	private static CloudFormationClient getMockCloudFormationClient(int createStackStatus,
			int deleteStackStatus, int describeStacksStatus, boolean describeStacksException,
			String describeStacksMessage) {
		CloudFormationClient cfClient = BDDMockito.mock(CloudFormationClient.class);
		BDDMockito.when(cfClient.serviceName()).thenReturn("cloudformation");
		BDDMockito.when(cfClient.createStack(BDDMockito.any(CreateStackRequest.class)))
				.thenReturn((CreateStackResponse) CreateStackResponse.builder().sdkHttpResponse(
						SdkHttpResponse.builder().statusCode(createStackStatus).build()).build());
		BDDMockito.when(cfClient.deleteStack(BDDMockito.any(DeleteStackRequest.class)))
				.thenReturn((DeleteStackResponse) DeleteStackResponse.builder().sdkHttpResponse(
						SdkHttpResponse.builder().statusCode(deleteStackStatus).build()).build());
		if (describeStacksException) {
			BDDMockito.doThrow(CloudFormationException.builder()
					.awsErrorDetails(AwsErrorDetails.builder()
							.errorCode("ValidationError")
							.errorMessage(describeStacksMessage)
							.serviceName("cloudformation").build())
					.statusCode(describeStacksStatus)
					.requestId("12345").build())
					.when(cfClient).describeStacks(BDDMockito.any(DescribeStacksRequest.class));
		} else {
			BDDMockito.when(cfClient.describeStacks(BDDMockito.any(DescribeStacksRequest.class)))
					.thenReturn((DescribeStacksResponse) DescribeStacksResponse.builder()
							.stacks(Stack.builder().stackStatus(describeStacksMessage).build())
							.sdkHttpResponse(
									SdkHttpResponse.builder().statusCode(describeStacksStatus)
											.build())
							.build());
		}
		BDDMockito.when(cfClient.waiter())
				.thenReturn(CloudFormationWaiter.builder().client(cfClient).build());
		return cfClient;
	}

	private static EcrClient getMockEcrClient(int describeFindingsStatus, boolean defaultAttributes,
			int deleteImageStatus, boolean deleteImageFailure) {
		EcrClient ecrClient = BDDMockito.mock(EcrClient.class);
		BDDMockito.when(ecrClient.serviceName()).thenReturn("ecr");
		BDDMockito.when(ecrClient.batchDeleteImage(BDDMockito.any(BatchDeleteImageRequest.class)))
				.thenReturn((BatchDeleteImageResponse) BatchDeleteImageResponse.builder()
						.failures(deleteImageFailure ? Collections.singletonList(
								ImageFailure.builder().failureReason("Cannot delete image").build())
								: Collections.emptyList())
						.sdkHttpResponse(SdkHttpResponse.builder()
								.statusCode(deleteImageStatus).build())
						.build());
		BDDMockito.when(ecrClient
				.describeImageScanFindings(BDDMockito.any(DescribeImageScanFindingsRequest.class)))
				.thenReturn((DescribeImageScanFindingsResponse) DescribeImageScanFindingsResponse
						.builder().imageScanFindings(ImageScanFindings.builder().findings(
								getMockImageFinding(defaultAttributes)).build())
						.sdkHttpResponse(
								SdkHttpResponse.builder().statusCode(describeFindingsStatus)
										.build())
						.build());

		BDDMockito.when(ecrClient.describeImageScanFindingsPaginator(
				BDDMockito.any(DescribeImageScanFindingsRequest.class)))
				.thenAnswer(i -> new DescribeImageScanFindingsIterable(ecrClient,
						(DescribeImageScanFindingsRequest) i.getArguments()[0]));
		return ecrClient;
	}

	private static ImageScanFinding getMockImageFinding(boolean defaultAttributes) {
		return ImageScanFinding.builder()
				.attributes(defaultAttributes ? Collections.emptyList()
						: Arrays.asList(
								Attribute.builder().key("package_name").value("a").build(),
								Attribute.builder().key("package_version").value("a").build(),
								Attribute.builder().key("CVSS2_SCORE").value("a").build(),
								Attribute.builder().key("CVSS2_VECTOR").value("a").build()))
				.severity(defaultAttributes ? FindingSeverity.HIGH : FindingSeverity.LOW)
				.name("findingName")
				.description("findingDescription")
				.uri("https://example.com")
				.build();
	}
}
