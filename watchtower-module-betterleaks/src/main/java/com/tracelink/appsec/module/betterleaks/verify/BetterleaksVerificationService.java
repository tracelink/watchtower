package com.tracelink.appsec.module.betterleaks.verify;

import java.time.Clock;
import java.util.Collection;
import java.util.Map;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.betterleaks.BetterleaksModule;
import com.tracelink.appsec.module.betterleaks.model.BetterleaksRuleDto;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.entity.PullRequestViolationEntity;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.repository.PRViolationRepository;
import com.tracelink.appsec.watchtower.core.verification.ILiveVerifier;
import com.tracelink.appsec.watchtower.core.verification.LiveVerificationStatus;

/**
 * "Verify live" for Betterleaks findings, answered by Betterleaks' own provider checks
 * ({@code --validation}) in {@link BetterleaksVerificationWorker}. This class only queues
 * requests and reports their state. Off unless {@link #ENABLED_PROPERTY} is true, because a
 * check sends the secret to its provider.
 *
 * @author Watchtower
 */
@Service
@ConditionalOnProperty(name = BetterleaksVerificationService.ENABLED_PROPERTY,
		havingValue = "true")
public class BetterleaksVerificationService implements ILiveVerifier {

	private static final Logger LOG = LoggerFactory.getLogger(BetterleaksVerificationService.class);

	public static final String ENABLED_PROPERTY = "watchtower.betterleaks.verification.enabled";

	public static final String MAX_REQUESTS_PROPERTY =
			"watchtower.betterleaks.verification.max-requests-per-hour";

	static final int DEFAULT_MAX_REQUESTS_PER_HOUR = 30;

	private static final long HOUR_MS = 3_600_000L;

	private final BetterleaksVerificationRepository repository;

	private final PRViolationRepository violations;

	private final VerifiableRules verifiableRules;

	private final int maxRequestsPerHour;

	private final Clock clock;

	@Autowired
	public BetterleaksVerificationService(BetterleaksVerificationRepository repository,
			PRViolationRepository violations, VerifiableRules verifiableRules,
			@Value("${" + MAX_REQUESTS_PROPERTY + ":" + DEFAULT_MAX_REQUESTS_PER_HOUR + "}")
			int maxRequestsPerHour) {
		this(repository, violations, verifiableRules, maxRequestsPerHour, Clock.systemUTC());
	}

	BetterleaksVerificationService(BetterleaksVerificationRepository repository,
			PRViolationRepository violations, VerifiableRules verifiableRules,
			int maxRequestsPerHour, Clock clock) {
		this.repository = repository;
		this.violations = violations;
		this.verifiableRules = verifiableRules;
		this.maxRequestsPerHour = maxRequestsPerHour;
		this.clock = clock;
	}

	@Override
	public String getPrivilegeName() {
		return BetterleaksModule.VERIFY_PRIVILEGE_NAME;
	}

	/**
	 * Only rules security allowed ({@link VerifiableRules}) are offered; every other finding
	 * shows no "Verify live" action at all.
	 */
	@Override
	public boolean supports(String ruleName) {
		return StringUtils.startsWith(ruleName, BetterleaksRuleDto.NAME_PREFIX)
				&& verifiableRules.isVerifiable(
						StringUtils.removeStart(ruleName, BetterleaksRuleDto.NAME_PREFIX));
	}

	@Override
	public LiveVerificationStatus request(long scanId, long violationId, String requestedBy) {
		PullRequestViolationEntity violation = violations.findById(violationId)
				// Same answer for "no such finding" and "not in this report".
				.filter(found -> found.getScan() != null && found.getScan().getId() == scanId)
				.orElseThrow(() -> new IllegalArgumentException("Unknown finding."));
		if (!supports(violation.getViolationName())) {
			throw new IllegalArgumentException("This finding cannot be verified live.");
		}
		BetterleaksVerificationEntity verification = repository.findByViolationId(violationId)
				.orElseGet(BetterleaksVerificationEntity::new);
		if (verification.getState() != null && verification.getState().isActive()) {
			return LiveVerificationStatus.PENDING;
		}
		long now = clock.millis();
		// Each check calls a third party from Watchtower's address; bound what one user can send.
		if (repository.countByRequestedByAndRequestedAtGreaterThan(requestedBy,
				now - HOUR_MS) >= maxRequestsPerHour) {
			throw new IllegalArgumentException("You have requested " + maxRequestsPerHour
					+ " live checks in the last hour; try again later.");
		}
		verification.setViolationId(violationId);
		verification.setRequestedBy(requestedBy);
		verification.setRequestedAt(now);
		verification.setAttempts(0);
		verification.setNextAttemptAt(now);
		verification.setLeaseUntil(null);
		verification.setLastError(null);
		verification.setState(BetterleaksVerificationState.PENDING);
		try {
			repository.save(verification);
		} catch (DataIntegrityViolationException e) {
			// Another request for the same finding was saved first.
			return LiveVerificationStatus.PENDING;
		}
		LOG.info("{} requested live verification of violation {}", requestedBy, violationId);
		return verification.getState().toStatus();
	}

	@Override
	public Map<Long, LiveVerificationStatus> getStatuses(Collection<Long> violationIds) {
		return repository.findByViolationIdIn(violationIds).stream()
				.collect(Collectors.toUnmodifiableMap(
						BetterleaksVerificationEntity::getViolationId,
						verification -> verification.getState().toStatus()));
	}
}
