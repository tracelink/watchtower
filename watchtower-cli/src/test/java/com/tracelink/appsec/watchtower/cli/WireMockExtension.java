package com.tracelink.appsec.watchtower.cli;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.VerificationException;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.Options;
import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import com.github.tomakehurst.wiremock.verification.NearMiss;
import java.util.List;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * Wiremock does not yet support JUnit 5 Extensions. This is a re-write of the JUnit 4 rule.
 *
 * @author csmith
 */
public class WireMockExtension extends WireMockServer
		implements BeforeEachCallback, AfterEachCallback {

	private final boolean failOnUnmatchedRequests;

	public WireMockExtension(Options options) {
		this(options, true);
	}

	public WireMockExtension(Options options, boolean failOnUnmatchedRequests) {
		super(options);
		this.failOnUnmatchedRequests = failOnUnmatchedRequests;
	}

	public WireMockExtension(int port) {
		this(wireMockConfig().port(port));
	}

	public WireMockExtension(int port, Integer httpsPort) {
		this(wireMockConfig().port(port).httpsPort(httpsPort));
	}

	public WireMockExtension() {
		this(wireMockConfig());
	}


	private void checkForUnmatchedRequests() {
		if (failOnUnmatchedRequests) {
			List<LoggedRequest> unmatchedRequests = findAllUnmatchedRequests();
			if (!unmatchedRequests.isEmpty()) {
				List<NearMiss> nearMisses = findNearMissesForAllUnmatchedRequests();
				if (nearMisses.isEmpty()) {
					throw VerificationException.forUnmatchedRequests(unmatchedRequests);
				} else {
					throw VerificationException.forUnmatchedNearMisses(nearMisses);
				}
			}
		}
	}

	@Override
	public void afterEach(ExtensionContext context) throws Exception {
		checkForUnmatchedRequests();
		stop();
	}

	@Override
	public void beforeEach(ExtensionContext context) throws Exception {
		start();
		if (options.getHttpDisabled()) {
			WireMock.configureFor("https", "localhost", httpsPort());
		} else {
			WireMock.configureFor("localhost", port());
		}

	}

}

