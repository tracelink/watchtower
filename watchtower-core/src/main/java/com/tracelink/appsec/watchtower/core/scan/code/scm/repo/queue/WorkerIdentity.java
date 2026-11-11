package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.queue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

/**
 * Names this pod in the rows it claims, so a heartbeat only refreshes work this pod owns and
 * logs show which pod ran a scan. The pod name (HOSTNAME in Kubernetes) plus a random suffix,
 * so two processes on one host still differ.
 *
 * @author Watchtower
 */
@Component
public class WorkerIdentity {

	private static final int MAX_LENGTH = 64;

	private final String id;

	public WorkerIdentity() {
		String host = System.getenv("HOSTNAME");
		if (StringUtils.isBlank(host)) {
			try {
				host = InetAddress.getLocalHost().getHostName();
			} catch (UnknownHostException e) {
				host = "watchtower";
			}
		}
		String suffix = "-" + UUID.randomUUID().toString().substring(0, 8);
		this.id = StringUtils.left(host, MAX_LENGTH - suffix.length()) + suffix;
	}

	public String id() {
		return id;
	}
}
