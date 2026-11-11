package com.tracelink.appsec.module.betterleaks.verify;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import com.tracelink.appsec.module.betterleaks.alerting.BetterleaksAlertListener;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksEngine;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksScanException;
import com.tracelink.appsec.module.betterleaks.engine.BetterleaksValidation;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleDto;
import com.tracelink.appsec.watchtower.core.alerting.AlertEvent;
import com.tracelink.appsec.watchtower.core.alerting.AlertItem;
import com.tracelink.appsec.watchtower.core.alerting.AlertService;
import com.tracelink.appsec.watchtower.core.alerting.AlertTypeRegistry;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationEntity;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.IScmApi;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.PullRequest;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestScanEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;
import com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;

/**
 * Runs queued live checks on its own thread, never a scan or scheduler thread. For each: re-read
 * the flagged file at the scanned commit, keep only the lines around the finding, and ask
 * Betterleaks' provider check whether that secret works. A live secret gets one follow-up pull
 * request comment and one {@link #SECRET_LIVE} alert. A check that keeps failing is retried
 * (1 min, 5 min) and then given up with a {@link #VERIFICATION_FAILED} alert.
 *
 * @author Watchtower
 */
@Component
@ConditionalOnProperty(name = BetterleaksVerificationService.ENABLED_PROPERTY,
		havingValue = "true")
public class BetterleaksVerificationWorker {

	private static final Logger LOG = LoggerFactory.getLogger(BetterleaksVerificationWorker.class);

	/** A secret found in a pull request was confirmed working by its provider. */
	public static final String SECRET_LIVE = "SECRET_LIVE";

	/** A live check was given up after repeated failures. */
	public static final String VERIFICATION_FAILED = "VERIFICATION_FAILED";

	static final String RESULTS_METRIC = "watchtower.betterleaks.verify.results";

	static final int MAX_ATTEMPTS = 3;

	/** Delay before attempt 2 and attempt 3. */
	private static final long[] RETRY_DELAYS_MS = {60_000L, 300_000L};

	/** Longer than a download plus the engine's own timeout, so a live run is never reclaimed. */
	private static final long LEASE_MS = 10 * 60_000L;

	private static final long POLL_SECONDS = 5;

	private static final String WINDOW_FILE = "window.txt";

	/** Larger files are not source a secret should be checked in; also bounds memory. */
	static final long MAX_FILE_BYTES = 5L * 1024 * 1024;

	private final BetterleaksVerificationRepository repository;

	private final PRViolationRepository violations;

	private final ApiIntegrationService integrations;

	private final VerifiableRules verifiableRules;

	private final BetterleaksEngine engine;

	private final AlertService alertService;

	private final String publicUrl;

	private final MeterRegistry meterRegistry;

	private final Clock clock;

	private ScheduledExecutorService executor;

	@Autowired
	public BetterleaksVerificationWorker(BetterleaksVerificationRepository repository,
			PRViolationRepository violations, ApiIntegrationService integrations,
			VerifiableRules verifiableRules, AlertService alertService,
			AlertTypeRegistry registry, @Value("${watchtower.publicUrl:#{null}}") String publicUrl,
			ObjectProvider<MeterRegistry> meterRegistry) {
		this(repository, violations, integrations, verifiableRules, new BetterleaksEngine(),
				alertService, registry, publicUrl, meterRegistry.getIfAvailable(),
				Clock.systemUTC());
	}

	BetterleaksVerificationWorker(BetterleaksVerificationRepository repository,
			PRViolationRepository violations, ApiIntegrationService integrations,
			VerifiableRules verifiableRules, BetterleaksEngine engine, AlertService alertService,
			AlertTypeRegistry registry, String publicUrl, MeterRegistry meterRegistry,
			Clock clock) {
		this.repository = repository;
		this.violations = violations;
		this.integrations = integrations;
		this.verifiableRules = verifiableRules;
		this.engine = engine;
		this.alertService = alertService;
		this.publicUrl = publicUrl;
		this.meterRegistry = meterRegistry;
		this.clock = clock;
		registry.register(SECRET_LIVE, "A secret found in a pull request was confirmed working"
				+ " by its provider (Verify live).", true);
		registry.register(VERIFICATION_FAILED, "A live secret check failed repeatedly and was"
				+ " given up.", false);
	}

	@PostConstruct
	void start() {
		executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
			Thread thread = new Thread(runnable, "betterleaks-verify");
			thread.setDaemon(true);
			return thread;
		});
		executor.scheduleWithFixedDelay(this::pollSafely, POLL_SECONDS, POLL_SECONDS,
				TimeUnit.SECONDS);
	}

	@PreDestroy
	void stop() {
		if (executor != null) {
			executor.shutdownNow();
		}
	}

	/** A failed poll is logged and retried next time; it must never kill the schedule. */
	void pollSafely() {
		try {
			poll();
		} catch (RuntimeException e) {
			LOG.error("Live verification poll failed", e);
		}
	}

	/**
	 * Releases abandoned checks, then claims and runs every due one.
	 */
	void poll() {
		long now = clock.millis();
		repository.releaseExpiredLeases(now, BetterleaksVerificationState.PENDING,
				BetterleaksVerificationState.RUNNING);
		List<BetterleaksVerificationEntity> due = repository
				.findTop10ByStateAndNextAttemptAtLessThanEqualOrderByNextAttemptAtAsc(
						BetterleaksVerificationState.PENDING, now);
		for (BetterleaksVerificationEntity verification : due) {
			if (repository.claim(verification.getId(), now, now + LEASE_MS,
					BetterleaksVerificationState.PENDING,
					BetterleaksVerificationState.RUNNING) == 1) {
				verification.setState(BetterleaksVerificationState.RUNNING);
				verification.setAttempts(verification.getAttempts() + 1);
				process(verification);
			}
		}
	}

	private void process(BetterleaksVerificationEntity verification) {
		try {
			Outcome outcome = check(verification);
			if (outcome.status() == LiveVerificationStatus.ERROR) {
				retryOrGiveUp(verification, "the provider check returned an error");
			} else {
				finish(verification, outcome);
			}
		} catch (CheckFailure e) {
			retryOrGiveUp(verification, e.getMessage());
		} catch (RuntimeException e) {
			LOG.warn("Live verification of violation {} failed", verification.getViolationId(),
					e);
			retryOrGiveUp(verification, "unexpected " + e.getClass().getSimpleName());
		}
	}

	/** What a check found, and where, for the follow-up. */
	private record Outcome(LiveVerificationStatus status, Target target) {
	}

	/** The finding to check, resolved to its pull request and SCM integration. */
	private record Target(PullRequestViolationEntity violation, long scanId, PullRequest pr,
			IScmApi api, String ruleId) {
	}

	/** A failure worth retrying: the SCM, the binary or the provider may recover. */
	private static final class CheckFailure extends Exception {
		private static final long serialVersionUID = 1L;

		CheckFailure(String message) {
			super(message);
		}
	}

	private Outcome check(BetterleaksVerificationEntity verification) throws CheckFailure {
		PullRequestViolationEntity violation =
				violations.findById(verification.getViolationId()).orElse(null);
		String ruleId = violation == null ? null : StringUtils.removeStart(
				violation.getViolationName(), BetterleaksRuleDto.NAME_PREFIX);
		if (!verifiableRules.isVerifiable(ruleId)) {
			// Gone, or no longer allowed since it was requested: never contact the provider.
			return new Outcome(LiveVerificationStatus.UNVERIFIABLE, null);
		}
		PullRequestScanEntity scan = violation.getScan();
		IScmApi api = scmApi(scan.getContainer().getApiLabel());
		if (StringUtils.isBlank(scan.getCommitHash()) || api == null) {
			// Scanned before commits were recorded, or its integration was removed.
			return new Outcome(LiveVerificationStatus.UNVERIFIABLE, null);
		}
		PullRequest pr = scan.getContainer().toPullRequest();
		pr.setCommitHash(scan.getCommitHash());
		Target target = new Target(violation, scan.getId(), pr, api, ruleId);
		return new Outcome(checkAtCommit(target), target);
	}

	private IScmApi scmApi(String apiLabel) {
		ApiIntegrationEntity integration = integrations.findByLabel(apiLabel);
		return integration != null && integration.createApi() instanceof IScmApi api ? api : null;
	}

	/**
	 * Works in an owner-only temp directory that is always deleted: the file as scanned lands in
	 * one sub-directory, the lines around the finding in another, and only the latter is checked.
	 */
	private LiveVerificationStatus checkAtCommit(Target target) throws CheckFailure {
		Path work = null;
		try {
			work = Files.createTempDirectory("watchtower-betterleaks-verify-",
					PosixFilePermissions.asFileAttribute(
							PosixFilePermissions.fromString("rwx------")));
			SecretWindow window = readWindow(target, Files.createDirectory(work.resolve("source")));
			if (window == null) {
				return LiveVerificationStatus.UNVERIFIABLE;
			}
			Path windowDir = Files.createDirectory(work.resolve("window"));
			Files.writeString(windowDir.resolve(WINDOW_FILE), window.text(),
					StandardCharsets.UTF_8);
			return engine.validate(windowDir, target.ruleId()).stream()
					.filter(result -> target.ruleId().equals(result.ruleId())
							&& result.startLine() == window.flaggedLine())
					.map(BetterleaksValidation::toStatus)
					.findFirst()
					// Not found where it was scanned: not the scanned secret, so no answer.
					.orElse(LiveVerificationStatus.UNVERIFIABLE);
		} catch (IOException e) {
			throw new CheckFailure("could not prepare the check: " + e.getMessage());
		} catch (BetterleaksScanException e) {
			throw new CheckFailure(e.getMessage());
		} finally {
			if (work != null) {
				FileUtils.deleteQuietly(work.toFile());
			}
		}
	}

	/**
	 * @return the lines around the finding, or null if the file cannot hold the scanned secret:
	 *         gone at the scanned commit (the SCM answered 404 - any other failure throws and is
	 *         retried), too large, binary, or not UTF-8
	 */
	private static SecretWindow readWindow(Target target, Path sourceDir) throws IOException {
		String fileName = target.violation().getFileName();
		target.api().downloadFileAtCommit(target.pr(), fileName, sourceDir);
		Path file = sourceDir.resolve(fileName).normalize();
		if (!file.startsWith(sourceDir) || !Files.isRegularFile(file)
				|| Files.size(file) > MAX_FILE_BYTES) {
			return null;
		}
		byte[] bytes = Files.readAllBytes(file);
		for (byte b : bytes) {
			if (b == 0) {
				return null;
			}
		}
		try {
			String content = StandardCharsets.UTF_8.newDecoder()
					.onMalformedInput(CodingErrorAction.REPORT)
					.onUnmappableCharacter(CodingErrorAction.REPORT)
					.decode(ByteBuffer.wrap(bytes)).toString();
			return SecretWindow.around(content, target.violation().getLineNum());
		} catch (CharacterCodingException e) {
			return null;
		}
	}

	private void finish(BetterleaksVerificationEntity verification, Outcome outcome) {
		long now = clock.millis();
		verification.setState(BetterleaksVerificationState.of(outcome.status()));
		verification.setVerifiedAt(now);
		verification.setLeaseUntil(null);
		verification.setLastError(null);
		if (outcome.status() == LiveVerificationStatus.LIVE
				&& verification.getNotifiedAt() == null) {
			announceLive(outcome.target());
			verification.setNotifiedAt(now);
		}
		repository.save(verification);
		count(outcome.status().name());
		LOG.info("Live verification of violation {}: {}", verification.getViolationId(),
				outcome.status());
	}

	private void retryOrGiveUp(BetterleaksVerificationEntity verification, String reason) {
		verification.setLeaseUntil(null);
		verification.setLastError(reason);
		if (verification.getAttempts() >= MAX_ATTEMPTS) {
			verification.setState(BetterleaksVerificationState.ERROR);
			verification.setVerifiedAt(clock.millis());
			repository.save(verification);
			count("gave_up");
			raiseGaveUp(verification, reason);
			return;
		}
		verification.setState(BetterleaksVerificationState.PENDING);
		verification.setNextAttemptAt(
				clock.millis() + RETRY_DELAYS_MS[verification.getAttempts() - 1]);
		repository.save(verification);
		count("retry");
	}

	private void announceLive(Target target) {
		PullRequestViolationEntity violation = target.violation();
		String location = violation.getFileName() + " line " + violation.getLineNum();
		if (!target.api().sendComment(target.pr(), "### Watchtower: live secret  \n"
				+ "The secret found by Betterleaks rule `" + target.ruleId() + "` in `"
				+ location + "` was confirmed **live** by its provider. Rotate it now -"
				+ " removing it from the code does not revoke it.")) {
			LOG.warn("Could not post the live-secret comment on {}", target.pr().getPRString());
		}
		alertService.raise(new AlertEvent(SECRET_LIVE, target.pr().getApiLabel(),
				target.pr().getRepoName(),
				"Live secret in pull request #" + target.pr().getPrId() + " - rotate now",
				BetterleaksAlertListener.reportLink(publicUrl, target.scanId()),
				BetterleaksAlertListener.threadKey(target.pr()),
				List.of(new AlertItem("live\u0000" + violation.getId(), violation.getSeverity(),
						"LIVE · " + target.ruleId() + " · " + location))));
	}

	private void raiseGaveUp(BetterleaksVerificationEntity verification, String reason) {
		PullRequest pr = violations.findById(verification.getViolationId())
				.map(violation -> violation.getScan().getContainer().toPullRequest())
				.orElse(null);
		alertService.raise(new AlertEvent(VERIFICATION_FAILED,
				pr == null ? null : pr.getApiLabel(), pr == null ? null : pr.getRepoName(),
				"Live secret check failed"
						+ (pr == null ? "" : " for pull request #" + pr.getPrId()),
				null, pr == null ? null : BetterleaksAlertListener.threadKey(pr),
				List.of(new AlertItem("failed\u0000" + verification.getId() + "\u0000"
						+ verification.getRequestedAt(), null,
						"Gave up after " + verification.getAttempts() + " attempts: " + reason))));
	}

	private void count(String result) {
		if (meterRegistry != null) {
			meterRegistry.counter(RESULTS_METRIC, "result", result.toLowerCase(Locale.ROOT))
					.increment();
		}
	}
}
