package com.tracelink.appsec.watchtower;

import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;

/** A continuously published heartbeat used by the missing-runtime-metrics alarm. */
@Component
public class RuntimeMetrics {
	private final AtomicInteger heartbeat = new AtomicInteger(1);

	public RuntimeMetrics(MeterRegistry registry) {
		Gauge.builder("watchtower.runtime.heartbeat", heartbeat, AtomicInteger::get)
				.description("Watchtower runtime metrics publisher heartbeat").register(registry);
	}

	@Scheduled(fixedRate = 60_000)
	void heartbeat() {
		heartbeat.set(1);
	}
}
