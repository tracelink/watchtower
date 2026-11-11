package com.tracelink.appsec.watchtower;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.micrometer.cloudwatch2.CloudWatchConfig;
import io.micrometer.cloudwatch2.CloudWatchMeterRegistry;
import io.micrometer.core.instrument.Clock;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudwatch.CloudWatchAsyncClient;

/** Publishes runtime/JVM metrics through the pod's IRSA credentials. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "watchtower.metrics.cloudwatch.enabled", havingValue = "true")
public class CloudWatchMetricsConfiguration {

	@Bean(destroyMethod = "close")
	CloudWatchAsyncClient cloudWatchClient(
			@Value("${watchtower.metrics.cloudwatch.region:us-east-1}") String region) {
		return CloudWatchAsyncClient.builder().region(Region.of(region))
				.credentialsProvider(DefaultCredentialsProvider.create()).build();
	}

	@Bean
	CloudWatchMeterRegistry cloudWatchMeterRegistry(CloudWatchAsyncClient client,
			@Value("${watchtower.metrics.cloudwatch.namespace:Watchtower/Runtime}") String namespace,
			@Value("${watchtower.metrics.cloudwatch.step:60s}") Duration step,
			@Value("${watchtower.metrics.environment:production}") String environment) {
		CloudWatchConfig config = new CloudWatchConfig() {
			@Override public String get(String key) { return null; }
			@Override public String namespace() { return namespace; }
			@Override public Duration step() { return step; }
		};
		CloudWatchMeterRegistry registry = new CloudWatchMeterRegistry(config, Clock.SYSTEM, client);
		registry.config().commonTags("application", "watchtower", "environment", environment);
		return registry;
	}
}
