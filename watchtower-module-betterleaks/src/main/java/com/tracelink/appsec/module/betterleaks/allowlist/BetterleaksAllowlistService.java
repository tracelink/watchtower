package com.tracelink.appsec.module.betterleaks.allowlist;

import java.time.Clock;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.betterleaks.model.BetterleaksProvidedRuleDto;
import com.tracelink.appsec.module.betterleaks.rules.BetterleaksProvidedRules;

/**
 * Manages the Betterleaks allowlist - the only sanctioned way to silence a secrets finding.
 * Inline {@code betterleaks:allow} comments and committed ignore files are deliberately
 * disabled, so every exception is made here, with a reason and an author, and is logged.
 *
 * @author Watchtower
 */
@Service
public class BetterleaksAllowlistService implements BetterleaksAllowlistProvider {

	private static final Logger LOG = LoggerFactory.getLogger(BetterleaksAllowlistService.class);

	static final int MAX_REASON_LENGTH = 500;

	static final int MAX_REPO_NAME_LENGTH = 255;

	static final int MAX_EXPIRY_DAYS = 365;

	/** Repository names as SCMs allow them; also keeps log lines free of injected text. */
	private static final Pattern REPO_NAME = Pattern.compile("[A-Za-z0-9._-]+");

	private final BetterleaksAllowlistRepository repository;

	private final Clock clock;

	private final Set<String> knownRuleIds;

	@Autowired
	public BetterleaksAllowlistService(BetterleaksAllowlistRepository repository) {
		this(repository, Clock.systemUTC());
	}

	BetterleaksAllowlistService(BetterleaksAllowlistRepository repository, Clock clock) {
		this.repository = repository;
		this.clock = clock;
		this.knownRuleIds = BetterleaksProvidedRules.load().rules().stream()
				.map(BetterleaksProvidedRuleDto::getBetterleaksId)
				.collect(Collectors.toUnmodifiableSet());
	}

	/**
	 * @return every entry, newest first, including expired ones
	 */
	public List<BetterleaksAllowlistEntryEntity> getEntries() {
		return repository.findAll().stream()
				.sorted(Comparator.comparingLong(BetterleaksAllowlistEntryEntity::getCreatedAt)
						.reversed())
				.toList();
	}

	/**
	 * @return the rule ids an entry may name
	 */
	public Set<String> getKnownRuleIds() {
		return knownRuleIds;
	}

	/**
	 * Validates and saves a new entry.
	 *
	 * @param request  the submitted entry
	 * @param username who is adding it
	 * @return the saved entry
	 * @throws IllegalArgumentException with a user-facing message if the request is invalid
	 */
	public BetterleaksAllowlistEntryEntity addEntry(BetterleaksAllowlistRequest request,
			String username) {
		if (request.scope() == null) {
			throw new IllegalArgumentException("Choose whether the entry is global or for one"
					+ " repository.");
		}
		String repoName = request.scope() == BetterleaksAllowlistScope.REPO
				? validRepoName(request.repoName())
				: null;
		String pathGlob = StringUtils.isBlank(request.pathGlob()) ? null
				: PathGlob.of(request.pathGlob()).glob();
		String ruleId = StringUtils.isBlank(request.ruleId()) ? null : validRuleId(request.ruleId());
		if (pathGlob == null && ruleId == null) {
			throw new IllegalArgumentException("An entry needs a path pattern, a rule, or both.");
		}
		String reason = StringUtils.trimToNull(request.reason());
		if (reason == null || reason.length() > MAX_REASON_LENGTH) {
			throw new IllegalArgumentException("A reason of up to " + MAX_REASON_LENGTH
					+ " characters is required.");
		}

		BetterleaksAllowlistEntryEntity entity = new BetterleaksAllowlistEntryEntity();
		entity.setScope(request.scope());
		entity.setRepoName(repoName);
		entity.setPathGlob(pathGlob);
		entity.setRuleId(ruleId);
		entity.setReason(reason);
		entity.setCreatedBy(username);
		entity.setCreatedAt(clock.millis());
		entity.setExpiresAt(expiryMillis(request.expiresOn()));
		BetterleaksAllowlistEntryEntity saved = repository.save(entity);
		// The reason is free text, so it is not logged; it is on the entry.
		LOG.info("Betterleaks allowlist entry {} added by {}: scope={} repo={} path={} rule={}"
				+ " expiresAt={}", saved.getId(), username, saved.getScope(), repoName, pathGlob,
				ruleId, saved.getExpiresAt());
		return saved;
	}

	/**
	 * @param id       the entry to delete
	 * @param username who is deleting it
	 * @throws IllegalArgumentException if no such entry exists
	 */
	public void deleteEntry(long id, String username) {
		BetterleaksAllowlistEntryEntity entry = repository.findById(id)
				.orElseThrow(() -> new IllegalArgumentException("No such allowlist entry."));
		repository.delete(entry);
		LOG.info("Betterleaks allowlist entry {} deleted by {}: scope={} repo={} path={} rule={}",
				id, username, entry.getScope(), entry.getRepoName(), entry.getPathGlob(),
				entry.getRuleId());
	}

	@Override
	public List<BetterleaksAllowlistEntry> activeEntries(String repositoryName) {
		long now = clock.millis();
		return repository.findAll().stream()
				.filter(entry -> !entry.isExpired(now))
				.filter(entry -> entry.getScope() == BetterleaksAllowlistScope.GLOBAL
						|| (repositoryName != null
								&& repositoryName.equalsIgnoreCase(entry.getRepoName())))
				.map(BetterleaksAllowlistEntryEntity::toEntry)
				.toList();
	}

	private static String validRepoName(String raw) {
		String repoName = StringUtils.trimToNull(raw);
		if (repoName == null || repoName.length() > MAX_REPO_NAME_LENGTH
				|| !REPO_NAME.matcher(repoName).matches()) {
			throw new IllegalArgumentException("A repository-scoped entry needs the repository"
					+ " name (letters, digits, '.', '_' and '-').");
		}
		return repoName;
	}

	private String validRuleId(String raw) {
		String ruleId = raw.trim();
		if (!knownRuleIds.contains(ruleId)) {
			// Not echoed back: it is unvalidated input.
			throw new IllegalArgumentException("Unknown Betterleaks rule.");
		}
		return ruleId;
	}

	private Long expiryMillis(LocalDate expiresOn) {
		if (expiresOn == null) {
			return null;
		}
		LocalDate today = LocalDate.now(clock.withZone(ZoneOffset.UTC));
		if (expiresOn.isBefore(today) || expiresOn.isAfter(today.plusDays(MAX_EXPIRY_DAYS))) {
			throw new IllegalArgumentException("The expiry must be between today and "
					+ MAX_EXPIRY_DAYS + " days from now.");
		}
		// Applies through the whole expiry day.
		return expiresOn.plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli();
	}
}
