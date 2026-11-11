package com.tracelink.appsec.watchtower.core.rule;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.ruleset.ImportOption;

/**
 * Handles logic to retrieve and delete rules, regardless of rule type.
 *
 * @author mcool
 */
@Service
public class RuleService {
	private static final Logger LOG = LoggerFactory.getLogger(RuleService.class);

	/**
	 * How long the in-memory rule cache is trusted before a read forces a refresh. Rules are
	 * also changed by other pods. Local module designers invalidate after saving; a short TTL
	 * bounds the staleness of reads on other pods without querying every rule on every read.
	 */
	private static final long RULE_CACHE_REFRESH_INTERVAL_MS = 60_000;

	private RuleRepository ruleRepository;
	private RuleStewardshipHistoryRepository stewardshipHistoryRepository;
	private com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory definitionHistory;

	@Autowired
	public void setDefinitionHistory(
			com.tracelink.appsec.watchtower.core.rule.candidate.RuleDefinitionHistory history) {
		this.definitionHistory = history;
	}

	@Autowired
	public void setStewardshipHistoryRepository(RuleStewardshipHistoryRepository repository) {
		this.stewardshipHistoryRepository = repository;
	}

	/** Module designers call this after saving; publish invalidation only after commit. */
	public void invalidateRuleCache() {
		if (TransactionSynchronizationManager.isSynchronizationActive()) {
			TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
				@Override
				public void afterCommit() { ruleCacheLoadedAtMillis = 0; }
			});
		} else {
			ruleCacheLoadedAtMillis = 0;
		}
	}

	@Transactional
	public void updateStewardship(long id, String module, RuleStewardshipUpdate update, String actor)
			throws RuleNotFoundException, RuleException {
		RuleEntity rule = ruleRepository.findById(id)
				.orElseThrow(() -> new RuleNotFoundException("No such rule exists."));
		if (!rule.toDto().getModule().equalsIgnoreCase(module)) {
			throw new RuleException("Unknown rule and module pair.");
		}
		try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
			if (!factory.getValidator().validate(update).isEmpty()) {
				throw new RuleException("Invalid stewardship. Check state, CWE and field lengths.");
			}
		}
		requireConsistentCwes(update);
		RuleStewardship metadata = rule.getStewardship();
		metadata.setState(update.state());
		metadata.setOwner(update.owner());
		metadata.setReviewBy(update.reviewBy());
		metadata.setCwe(update.cwe());
		metadata.setSecondaryCwes(update.secondaryCwes());
		metadata.setSecurityRelevance(update.notSecurity() ? RuleStewardship.NOT_SECURITY : null);
		metadata.setCategory(update.category());
		ruleRepository.saveAndFlush(rule);
		stewardshipHistoryRepository.saveAndFlush(new RuleStewardshipHistoryEntity(rule, actor));
		invalidateRuleCache();
	}

	private static boolean isBlank(String value) {
		return value == null || value.isBlank();
	}

	/** Secondary CWEs need a primary one and differ from it and from each other; a non-security rule has none. */
	private static void requireConsistentCwes(RuleStewardshipUpdate update) throws RuleException {
		if (update.secondaryCwes() != null) {
			if (update.cwe() == null) {
				throw new RuleException("Set a primary CWE before adding secondary ones.");
			}
			List<String> secondary = List.of(update.secondaryCwes().split(","));
			if (new HashSet<>(secondary).size() != secondary.size() || secondary.contains(update.cwe())) {
				throw new RuleException("Secondary CWEs must differ from each other and from the primary CWE.");
			}
		}
		if (update.notSecurity() && (update.cwe() != null || update.secondaryCwes() != null)) {
			throw new RuleException("A rule that is not a security rule has no CWE.");
		}
	}

	/**
	 * Applies the answers a person confirmed in Rule work → Suggest CWEs: a CWE for some rules, and "not a
	 * security rule" for others. Rules that already have a CWE are left as they are. All CWEs are checked first,
	 * and everything changes in one transaction with one history row per rule.
	 *
	 * @param cwes        rule id to the CWE to set
	 * @param notSecurity rules to mark as not security rules
	 * @return how many rules changed
	 */
	@Transactional(rollbackFor = Exception.class)
	public int applySuggestions(Map<Long, String> cwes, Collection<Long> notSecurity, String actor)
			throws RuleNotFoundException, RuleException {
		Set<Long> marked = notSecurity == null ? Set.of() : new HashSet<>(notSecurity);
		Map<Long, String> chosen = cwes == null ? Map.of() : cwes;
		if (chosen.size() + marked.size() < 1 || chosen.size() + marked.size() > MAX_BULK_STEWARDSHIP) {
			throw new RuleException("Select between 1 and " + MAX_BULK_STEWARDSHIP + " rules.");
		}
		if (marked.stream().anyMatch(chosen::containsKey)) {
			throw new RuleException("A rule cannot both get a CWE and be marked as not a security rule.");
		}
		java.util.regex.Pattern format = java.util.regex.Pattern.compile("CWE-[1-9][0-9]{0,8}");
		for (String cwe : chosen.values()) {
			if (cwe == null || !format.matcher(cwe).matches()) {
				throw new RuleException("Each CWE must look like CWE-79.");
			}
		}
		int changed = chosen.isEmpty() ? 0 : applyCwes(chosen, actor);
		if (marked.isEmpty()) {
			return changed;
		}
		List<RuleEntity> found = ruleRepository.findAllById(marked);
		if (found.size() != marked.size()) {
			throw new RuleNotFoundException("Some selected rules no longer exist. Reload the page and try again.");
		}
		List<RuleEntity> toMark = found.stream()
				.filter(rule -> rule.getStewardship().getCwe() == null || rule.getStewardship().getCwe().isBlank())
				.filter(rule -> !rule.getStewardship().isNotSecurity()).toList();
		for (RuleEntity rule : toMark) {
			rule.getStewardship().setSecurityRelevance(RuleStewardship.NOT_SECURITY);
			rule.getStewardship().setSecondaryCwes(null);
		}
		if (!toMark.isEmpty()) {
			ruleRepository.saveAllAndFlush(toMark);
			stewardshipHistoryRepository
					.saveAllAndFlush(toMark.stream().map(rule -> new RuleStewardshipHistoryEntity(rule, actor)).toList());
			invalidateRuleCache();
		}
		return changed + toMark.size();
	}

	/** Most rules one bulk owner/CWE change may touch: one page of Rule work. */
	public static final int MAX_BULK_STEWARDSHIP = 100;

	/**
	 * Sets the owner and/or CWE of several rules at once (Rule work → Setup gaps). A blank value
	 * keeps each rule's own; every other stewardship field is left as it is. All rules change in
	 * one transaction with one history row each, or none change.
	 *
	 * @return how many rules were updated
	 */
	@Transactional
	public int setOwnerAndCwe(Collection<Long> ids, String owner, String cwe, String actor)
			throws RuleNotFoundException, RuleException {
		return setOwnerAndCwe(ids, owner, cwe, false, actor);
	}

	/**
	 * As {@link #setOwnerAndCwe(Collection, String, String, String)}, and optionally marks the rules as not
	 * security rules. Rules that already have a CWE are left out of a "not a security rule" change.
	 */
	@Transactional
	public int setOwnerAndCwe(Collection<Long> ids, String owner, String cwe, boolean notSecurity, String actor)
			throws RuleNotFoundException, RuleException {
		Set<Long> unique = ids == null ? Set.of() : new HashSet<>(ids);
		if (unique.isEmpty() || unique.size() > MAX_BULK_STEWARDSHIP) {
			throw new RuleException("Select between 1 and " + MAX_BULK_STEWARDSHIP + " rules.");
		}
		// Reuse the single-rule form's rules for owner length and CWE format.
		RuleStewardshipUpdate values = new RuleStewardshipUpdate(RuleState.ACTIVE, owner, null, cwe, null);
		try (ValidatorFactory factory = Validation.buildDefaultValidatorFactory()) {
			if (!factory.getValidator().validate(values).isEmpty()) {
				throw new RuleException("Check the owner (at most 255 characters) and the CWE (like CWE-79).");
			}
		}
		if (notSecurity && values.cwe() != null) {
			throw new RuleException("A rule that is not a security rule has no CWE.");
		}
		if (values.owner() == null && values.cwe() == null && !notSecurity) {
			throw new RuleException("Enter an owner, a CWE or both.");
		}
		List<RuleEntity> rules = ruleRepository.findAllById(unique);
		if (rules.size() != unique.size()) {
			throw new RuleNotFoundException("Some selected rules no longer exist. Reload the page and try again.");
		}
		if (notSecurity) {
			rules = rules.stream().filter(rule -> isBlank(rule.getStewardship().getCwe())).toList();
		}
		List<RuleStewardshipHistoryEntity> history = new java.util.ArrayList<>(rules.size());
		for (RuleEntity rule : rules) {
			RuleStewardship metadata = rule.getStewardship();
			if (notSecurity) {
				metadata.setSecurityRelevance(RuleStewardship.NOT_SECURITY);
				metadata.setSecondaryCwes(null);
			}
			if (values.owner() != null) {
				metadata.setOwner(values.owner());
			}
			if (values.cwe() != null) {
				metadata.setCwe(values.cwe());
				// A rule that has a CWE is a security rule.
				metadata.setSecurityRelevance(null);
			}
		}
		ruleRepository.saveAllAndFlush(rules);
		rules.forEach(rule -> history.add(new RuleStewardshipHistoryEntity(rule, actor)));
		stewardshipHistoryRepository.saveAllAndFlush(history);
		invalidateRuleCache();
		return rules.size();
	}

	/**
	 * Applies a CWE to each listed rule that still has none (Rule work → Suggest CWEs). Every CWE is
	 * checked first, then all rules change in one transaction through {@link #setOwnerAndCwe}, so each
	 * gets one history row. A rule that gained a CWE since it was suggested is left alone, not replaced.
	 *
	 * @return how many rules were updated; the rest were skipped
	 */
	@Transactional(rollbackFor = Exception.class)
	public int applyCwes(Map<Long, String> assignments, String actor)
			throws RuleNotFoundException, RuleException {
		if (assignments == null || assignments.isEmpty() || assignments.size() > MAX_BULK_STEWARDSHIP) {
			throw new RuleException("Select between 1 and " + MAX_BULK_STEWARDSHIP + " rules.");
		}
		java.util.regex.Pattern format = java.util.regex.Pattern.compile("CWE-[1-9][0-9]{0,8}");
		for (String cwe : assignments.values()) {
			if (cwe == null || !format.matcher(cwe).matches()) {
				throw new RuleException("Each CWE must look like CWE-79.");
			}
		}
		List<RuleEntity> rules = ruleRepository.findAllById(assignments.keySet());
		if (rules.size() != assignments.size()) {
			throw new RuleNotFoundException("Some selected rules no longer exist. Reload the page and try again.");
		}
		Map<String, List<Long>> byCwe = new java.util.LinkedHashMap<>();
		for (RuleEntity rule : rules) {
			String current = rule.getStewardship().getCwe();
			if (current == null || current.isBlank()) {
				byCwe.computeIfAbsent(assignments.get(rule.getId()), key -> new java.util.ArrayList<>())
						.add(rule.getId());
			}
		}
		int changed = 0;
		for (Map.Entry<String, List<Long>> group : byCwe.entrySet()) {
			changed += setOwnerAndCwe(group.getValue(), "", group.getKey(), actor);
		}
		return changed;
	}

	/** Upstream removal preserves logical identity and local review evidence. */
	@Transactional
	public void retireRule(long id) throws RuleNotFoundException {
		RuleEntity rule = ruleRepository.findById(id)
				.orElseThrow(() -> new RuleNotFoundException("No such rule exists."));
		if (rule.getStewardship().getState() == RuleState.RETIRED) {
			return;
		}
		rule.getStewardship().setState(RuleState.RETIRED);
		ruleRepository.saveAndFlush(rule);
		stewardshipHistoryRepository.saveAndFlush(new RuleStewardshipHistoryEntity(rule, "system"));
		invalidateRuleCache();
	}

	private volatile Map<String, RuleEntity> ruleCacheByName = Collections.emptyMap();
	private volatile Map<Long, RuleEntity> ruleCacheById = Collections.emptyMap();
	// Listing methods (getRules/getRulesForModule) deliberately read this instead of
	// ruleCacheById.values(): a Map can only hold one entry per id, so any two rows that ever
	// collided on id would silently drop one from a "list everything" view. A plain list has no
	// such assumption.
	private volatile List<RuleEntity> ruleCacheAll = Collections.emptyList();
	private final Map<Class<?>, String> modulesByType = new java.util.concurrent.ConcurrentHashMap<>();
	private final Map<Class<?>, RuleDesignation> designationsByType = new java.util.concurrent.ConcurrentHashMap<>();
	private volatile long ruleCacheLoadedAtMillis = 0;

	/**
	 * Creates an instance of this service with a {@link RuleRepository}.
	 *
	 * @param ruleRepository repository to interact with the database
	 */
	public RuleService(@Autowired RuleRepository ruleRepository) {
		this.ruleRepository = ruleRepository;
	}

	private List<CustomRuleValidator> customRuleValidators = List.of();

	/**
	 * @param validators module validators applied to imported rules (see
	 *                   {@link CustomRuleValidator})
	 */
	@Autowired(required = false)
	public void setCustomRuleValidators(List<CustomRuleValidator> validators) {
		this.customRuleValidators = validators == null ? List.of() : List.copyOf(validators);
	}

	/**
	 * Warms the rule cache at application startup instead of leaving it to the first caller to
	 * pay for lazily - the rules table is small reference data, so this is cheap, and it means
	 * the very first PR scan report/page load after a deploy or restart doesn't eat the cold
	 * cache cost.
	 * <p>
	 * Deliberately {@code ApplicationReadyEvent} and not {@code @PostConstruct}: each module
	 * creates its own rule table from its own Flyway migration inside
	 * {@link com.tracelink.appsec.watchtower.core.module.AbstractModule#buildModule()}, which is
	 * itself a {@code @PostConstruct}. Warming from a {@code @PostConstruct} here raced those and
	 * queried the rule hierarchy before, for example, ADVISORY_RULES existed, failing startup
	 * outright on a fresh database. This event fires only once the whole context - every module
	 * migration included - has finished refreshing.
	 */
	@EventListener(ApplicationReadyEvent.class)
	void warmRuleCache() {
		refreshRuleCache();
		// Observe today's baseline after module migrations. This does not reconstruct past edits.
		if (definitionHistory != null) {
			for (RuleEntity rule : ruleCacheAll) definitionHistory.record(rule.toDto());
		}
	}

	/**
	 * Rebuilds the in-memory rule cache from the database if it is older than
	 * {@link #RULE_CACHE_REFRESH_INTERVAL_MS}. Cheap to call on every read - the age check is a
	 * single volatile read, and only the (rare) thread that actually needs to refresh pays for
	 * the query, via double-checked locking.
	 */
	private void ensureRuleCacheFresh() {
		if (System.currentTimeMillis() - ruleCacheLoadedAtMillis < RULE_CACHE_REFRESH_INTERVAL_MS) {
			return;
		}
		synchronized (this) {
			if (System.currentTimeMillis()
					- ruleCacheLoadedAtMillis < RULE_CACHE_REFRESH_INTERVAL_MS) {
				return;
			}
			refreshRuleCache();
		}
	}

	/**
	 * Unconditionally reloads the in-memory rule cache from the database. Called directly (not
	 * through {@link #ensureRuleCacheFresh()}) after this class's own writes, so a delete or
	 * import made here is reflected immediately rather than waiting out the TTL.
	 */
	private synchronized void refreshRuleCache() {
		List<RuleEntity> all = ruleRepository.findAll();
		// Names compare ignoring case, as MySQL's findByName does: a collision check here must
		// refuse "SQL-Injection" next to "sql-injection", or later imports find two rules
		Map<String, RuleEntity> byName = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
		Map<Long, RuleEntity> byId = new HashMap<>();
		for (RuleEntity rule : all) {
			byName.put(rule.getName(), rule);
			byId.put(rule.getId(), rule);
		}
		this.ruleCacheByName = byName;
		this.ruleCacheById = byId;
		this.ruleCacheAll = all;
		this.ruleCacheLoadedAtMillis = System.currentTimeMillis();
	}

	/**
	 * Gets a list of all rules. Each rule is translated into a {@link RuleDto} for convenience.
	 *
	 * @return list of DTOs for all rules in the database
	 */
	public List<RuleDto> getRules() {
		ensureRuleCacheFresh();
		return Collections.unmodifiableList(
				ruleCacheAll.stream().map(RuleEntity::toDto).sorted()
						.collect(Collectors.toList()));
	}

	/**
	 * Gets the rule with the given ID.
	 *
	 * @param id ID of the rule to retrieve
	 * @return rule with the given ID
	 * @throws RuleNotFoundException if no rule with the given ID exists
	 */
	public RuleEntity getRule(long id) throws RuleNotFoundException {
		ensureRuleCacheFresh();
		RuleEntity rule = ruleCacheById.get(id);
		if (rule == null) {
			throw new RuleNotFoundException("No such rule exists.");
		}
		return rule;
	}

	/**
	 * Whether the rule's definition, guidance included, was seen to change after a scan ran. False when
	 * that cannot be known, for example when the rule was first observed after the scan.
	 */
	public boolean changedAfter(RuleEntity rule, long scannedAtMillis) {
		return definitionHistory != null && rule != null
				&& definitionHistory.changedAfter(rule.getId(), scannedAtMillis);
	}

	/** Revision-bound workflows must not validate a write against the display cache. */
	@Transactional(readOnly = true)
	public RuleEntity getCurrentRule(long id) throws RuleNotFoundException {
		return ruleRepository.findById(id).orElseThrow(() -> new RuleNotFoundException("No such rule exists."));
	}

	/**
	 * Gets the rule with the given name.
	 *
	 * @param name name of the rule to retrieve
	 * @return rule with the given name, or null if not found
	 */
	public RuleEntity getRule(String name) {
		ensureRuleCacheFresh();
		return ruleCacheByName.get(name);
	}

	/**
	 * Gets every rule matching one of the given names, from the in-memory cache instead of a
	 * database query. Intended for callers (like PR scan result rendering) that need rule
	 * guidance for many distinct names at once.
	 *
	 * @param names the rule names to look up
	 * @return the rules matching any of the given names; names with no matching rule are simply
	 * absent, not represented as null entries
	 */
	public List<RuleEntity> getRulesByNames(Collection<String> names) {
		ensureRuleCacheFresh();
		return names.stream().map(ruleCacheByName::get).filter(r -> r != null)
				.collect(Collectors.toList());
	}

	/**
	 * Counts rules per module from the rule cache (Scanner modules links each module to its rules).
	 *
	 * @return lower-case module name to its number of rules
	 */
	public Map<String, Long> countRulesByModule() {
		ensureRuleCacheFresh();
		return ruleCacheAll.stream().map(RuleEntity::toDto).collect(Collectors.groupingBy(
				r -> r.getModule().toLowerCase(java.util.Locale.ROOT), Collectors.counting()));
	}

	/** How many of the given rules each module owns (module name as the module reports it). */
	public Map<String, Long> countModulesOf(Collection<Long> ruleIds) {
		ensureRuleCacheFresh();
		Map<String, Long> counts = new TreeMap<>();
		for (Long id : ruleIds) {
			RuleEntity rule = ruleCacheById.get(id);
			if (rule != null) {
				counts.merge(rule.toDto().getModule(), 1L, Long::sum);
			}
		}
		return counts;
	}

	/** The module whose rules are stored as this rule entity subclass, or "Unknown". */
	public String moduleOfType(Class<?> type) {
		if (type == null) {
			return "Unknown";
		}
		String known = modulesByType.get(type);
		if (known != null) {
			return known;
		}
		ensureRuleCacheFresh();
		String module = ruleCacheAll.stream().filter(rule -> org.hibernate.Hibernate.getClass(rule).equals(type))
				.findFirst().map(rule -> rule.toDto().getModule()).orElseGet(() -> moduleOfStoredType(type));
		if (module != null) {
			// A rule class always belongs to the same module, so the answer never goes stale.
			modulesByType.put(type, module);
		}
		return module == null ? "Unknown" : module;
	}

	/** A rule created after the cache last loaded: read one rule of that class to name its module. */
	private String moduleOfStoredType(Class<?> type) {
		RuleDto stored = oneStoredRuleOf(type);
		return stored == null ? null : stored.getModule();
	}

	private RuleDto oneStoredRuleOf(Class<?> type) {
		if (!RuleEntity.class.isAssignableFrom(type)) {
			return null;
		}
		List<Long> ids = ruleRepository.findIdsByType(type.asSubclass(RuleEntity.class),
				org.springframework.data.domain.PageRequest.of(0, 1));
		return ids.isEmpty() ? null : ruleRepository.findById(ids.get(0)).map(RuleEntity::toDto).orElse(null);
	}

	/**
	 * Whether rules stored as this rule entity subclass are custom or provided, or null when no rule
	 * of that class exists. For most classes it is always one or the other, so the answer is
	 * remembered; classes that mix both report per rule in {@link #designationsOfMixedRules()}.
	 */
	public RuleDesignation designationOfType(Class<?> type) {
		if (type == null) {
			return null;
		}
		RuleDesignation known = designationsByType.get(type);
		if (known != null) {
			return known;
		}
		ensureRuleCacheFresh();
		RuleDesignation designation = ruleCacheAll.stream()
				.filter(rule -> org.hibernate.Hibernate.getClass(rule).equals(type)).findFirst()
				.map(rule -> rule.toDto().getRuleDesignation()).orElseGet(() -> {
					RuleDto stored = oneStoredRuleOf(type);
					return stored == null ? null : stored.getRuleDesignation();
				});
		if (designation != null) {
			designationsByType.put(type, designation);
		}
		return designation;
	}

	/**
	 * Designation of each rule whose class mixes custom and provided rules, by rule id. Other rules
	 * are absent: their designation is that of their class ({@link #designationOfType(Class)}).
	 */
	public Map<Long, RuleDesignation> designationsOfMixedRules() {
		ensureRuleCacheFresh();
		Map<Long, RuleDesignation> mixed = new java.util.HashMap<>();
		for (RuleEntity rule : ruleCacheAll) {
			RuleDesignation own = rule.designationOfThisRule();
			if (own != null) {
				mixed.put(rule.getId(), own);
			}
		}
		return mixed;
	}

	/** The rule entity subclasses a module stores its rules as, for filtering queries by scanner. */
	public List<Class<? extends RuleEntity>> ruleTypesOfModule(String module) {
		ensureRuleCacheFresh();
		return ruleCacheAll.stream().filter(rule -> rule.toDto().getModule().equalsIgnoreCase(module))
				.<Class<? extends RuleEntity>>map(rule -> org.hibernate.Hibernate.getClass(rule)
						.asSubclass(RuleEntity.class))
				.distinct().toList();
	}

	public List<RuleDto> getRulesForModule(String module) {
		ensureRuleCacheFresh();
		return ruleCacheAll.stream().map(RuleEntity::toDto)
				.filter(r -> r.getModule().equalsIgnoreCase(module)).sorted()
				.collect(Collectors.toList());
	}

	/**
	 * Deletes the rule with the given ID.
	 *
	 * @param id ID of the rule to delete
	 * @throws RuleNotFoundException if no rule with the given ID exists
	 */
	@Transactional
	public void deleteRule(long id) throws RuleNotFoundException {
		// The current row, not the display cache: a cached copy older than an edit has a stale
		// version and the delete fails with an optimistic-lock error.
		RuleEntity rule = getCurrentRule(id);
		ruleRepository.delete(rule);
		invalidateRuleCache();
	}

	/**
	 * Determines whether changing the name of the rule with the given ID to the given name will
	 * result in a name collision. Used to prevent multiple rules in the database from having the
	 * same name.
	 *
	 * @param id   ID of the rule to edit
	 * @param name proposed new name for the rule with the given ID
	 * @return true if a different rule in the database already has the given name, false otherwise
	 */
	public boolean createsNameCollision(long id, String name) {
		RuleEntity rule = getRule(name);
		return rule != null && rule.getId() != id;
	}


	/**
	 * The validation messages an import of these rules would fail with, without importing them.
	 * Used by the ruleset import preview.
	 */
	public List<String> validationProblems(Set<RuleDto> ruleDtos) {
		try {
			validateRules(ruleDtos);
			return List.of();
		} catch (RuleException e) {
			return java.util.Arrays.stream(e.getMessage().split("\n")).skip(1).map(String::strip)
					.filter(line -> !line.isEmpty()).toList();
		}
	}

	private <T extends RuleDto> void validateRules(Set<T> ruleDtos) throws RuleException {
		ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
		Validator validator = validatorFactory.getValidator();
		// Validate fields of the rule
		StringBuilder sb = new StringBuilder();
		for (T ruleDto : ruleDtos) {
			Set<ConstraintViolation<T>> violations = validator.validate(ruleDto);
			if (!violations.isEmpty()) {
				sb.append("\nRule: " + ruleDto.getName() + " violations: ");
				sb.append(violations.stream().map(v -> v.getMessage())
						.collect(Collectors.joining(", ")));
				continue;
			}
			for (CustomRuleValidator moduleValidator : customRuleValidators) {
				if (moduleValidator.supports(ruleDto)) {
					try {
						moduleValidator.validate(ruleDto);
					} catch (RuleException e) {
						sb.append("\nRule: " + ruleDto.getName() + " violations: "
								+ e.getMessage());
					}
				}
			}
		}
		if (sb.length() > 0) {
			throw new RuleException("One or more rules are invalid." + sb.toString());
		}
	}

	/**
	 * Imports the given set of rule DTOs and stores each in the database. For each new rule entity,
	 * assign the given user as the author of the rule.
	 *
	 * @param dtos             set of rule DTOs to import
	 * @param backupAuthorName name to assign as author of the rules, if it is not part of the given
	 *                         rule
	 * @param customOption     the option used during custom rule imports
	 * @param providedOption   the option used during provided rule imports
	 * @return list of database entity rules that have been imported
	 * @throws RuleException if there is a rule that already exists with the same name
	 */
	@Transactional(rollbackFor = RuleException.class)
	public List<RuleEntity> importRules(Set<RuleDto> dtos, String backupAuthorName,
			ImportOption customOption, ImportOption providedOption)
			throws RuleException {
		// ensure authors are set correctly
		dtos.stream()
				.filter(r -> (RuleDesignation.CUSTOM.equals(r.getRuleDesignation())
						&& StringUtils.isBlank(r.getAuthor())))
				.forEach(r -> ((CustomRuleDto) r).setAuthor(backupAuthorName));

		validateRules(dtos);

		Set<RuleEntity> rules = new HashSet<>();
		for (RuleDto rule : dtos) {
			LOG.debug("Importing Rule {}", rule.getName());
			RuleEntity found = ruleRepository.findByName(rule.getName());
			if (found != null) {
				if (!found.toDto().getModule().equalsIgnoreCase(rule.getModule())) {
					throw new RuleException("A rule with this name already belongs to another module.");
				}
				if (rule.getRuleDesignation().equals(RuleDesignation.PROVIDED)) {
					// On update, only update the priority
					if (providedOption.equals(ImportOption.SKIP)) {
						LOG.debug("Skipping update of provided rule {}", rule.getName());
					} else if (providedOption.equals(ImportOption.UPDATE)) {
						found.setPriority(rule.getPriority());
						rules.add(found);
					} else if (providedOption.equals(ImportOption.OVERRIDE)) {
						// update the old rule with the new info
						RuleEntity ruleEntity = rule.toEntity();
						ruleEntity.setId(found.getId());
						ruleEntity.preserveStewardshipFrom(found);
						ruleEntity.getRulesets().addAll(found.getRulesets());
						ruleEntity.setPriority(found.getPriority());
						rules.add(ruleEntity);
					}
				} else {
					if (customOption.equals(ImportOption.SKIP)) {
						// don't update, just skip
						LOG.debug("Skipping update of rule {}", rule.getName());
					} else {
						// update the old rule with the new info
						RuleEntity ruleEntity = rule.toEntity();
						ruleEntity.setId(found.getId());
						ruleEntity.preserveStewardshipFrom(found);
						ruleEntity.getRulesets().addAll(found.getRulesets());
						rules.add(ruleEntity);
					}
				}
			} else {
				// new rule
				RuleEntity ruleEntity = rule.toEntity();
				// Exported numeric ids belong to their installation, never to this new row.
				ruleEntity.setId(0);
				rules.add(ruleEntity);
			}
		}
		rules.forEach(RuleEntity::refreshRevision);
		List<RuleEntity> saveRules = ruleRepository.saveAll(rules);
		ruleRepository.flush();
		invalidateRuleCache();
		return saveRules;
	}

}
