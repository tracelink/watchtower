package com.tracelink.appsec.watchtower.core.ruleset;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.util.Strings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.util.StreamUtils;

import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleException;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.scm.RepositoryRepository;

/**
 * Handles logic to retrieve and edit rulesets.
 *
 * @author mcool
 */
@Service
public class RulesetService {
	private static final Logger LOG = LoggerFactory.getLogger(RulesetService.class);

	private RulesetRepository rulesetRepository;
	private RuleService ruleService;
	private RepositoryRepository repositoryRepository;
	private JsonMapper mapper;

	/**
	 * Creates an instance of this service with a {@link RulesetRepository} and a
	 * {@link RuleService}.
	 *
	 * @param rulesetRepository    repository to interact with the database
	 * @param ruleService          service to retrieve rules
	 * @param repositoryRepository repo repository to remove references to rulesets on delete
	 */
	public RulesetService(@Autowired RulesetRepository rulesetRepository,
			@Autowired RuleService ruleService,
			@Autowired RepositoryRepository repositoryRepository) {
		this.rulesetRepository = rulesetRepository;
		this.ruleService = ruleService;
		this.repositoryRepository = repositoryRepository;
		PolymorphicTypeValidator validator = createTypeValidator();
		mapper = JsonMapper.builder().polymorphicTypeValidator(validator)
				.activateDefaultTyping(validator).build();
	}

	private PolymorphicTypeValidator createTypeValidator() {
		return BasicPolymorphicTypeValidator.builder()
				.allowIfBaseType(RuleDto.class)
				.allowIfBaseType(Set.class)
				.allowIfBaseType(RulesetDto.class)
				.build();
	}

	/**
	 * Gets a list of all rulesets in the database. Each ruleset is translated into a
	 * {@link RulesetDto} for convenience.
	 *
	 * @return list of DTOs for all rulesets in the database
	 */
	public List<RulesetDto> getRulesets() {
		List<RulesetDto> rulesets =
				rulesetRepository.findAll().stream().map(RulesetEntity::toDto).sorted()
						.collect(Collectors.toList());
		return Collections.unmodifiableList(rulesets);
	}

	/**
	 * Creates a new ruleset with the given name and description, if a ruleset does not already
	 * exist with the given name.
	 *
	 * @param name        name of the new ruleset
	 * @param description description of the new ruleset
	 * @param designation designation of the new ruleset
	 * @return ruleset that is created
	 * @throws RulesetException if a ruleset already exists with that name, or if the designation is
	 *                          "Default" and there is already a default ruleset
	 */
	public RulesetEntity createRuleset(String name, String description,
			RulesetDesignation designation) throws RulesetException {
		if (StringUtils.isBlank(name) || StringUtils.isBlank(description) || designation == null) {
			throw new IllegalArgumentException(
					"Please provide a ruleset name, description and designation that are not null or empty.");
		}
		// Check if trying to create default
		if (designation.equals(RulesetDesignation.DEFAULT)) {
			throw new RulesetException(
					"A ruleset must be created as either primary or supporting.");
		}
		// Check for name collisions

		RulesetEntity ruleset = rulesetRepository.findByName(name);
		if (ruleset == null) {
			ruleset = new RulesetEntity();
			ruleset.setName(name);
			ruleset.setDescription(description);
			ruleset.setDesignation(designation);

			rulesetRepository.saveAndFlush(ruleset);
			return ruleset;
		}
		throw new RulesetException("A ruleset with the name \"" + name + "\" already exists.");
	}

	/**
	 * Deletes the ruleset with the given ID.
	 *
	 * @param id ID of the ruleset to delete
	 * @throws RulesetNotFoundException if no ruleset with the given ID exists
	 * @throws RulesetException         if the id belongs to a Provided ruleset
	 */
	public void deleteRuleset(long id) throws RulesetNotFoundException, RulesetException {
		RulesetEntity ruleset = getRuleset(id);
		if (ruleset.getDesignation().equals(RulesetDesignation.PROVIDED)) {
			throw new RulesetException("Cannot delete a Provided ruleset");
		}
		deleteRulesetInternal(ruleset);
	}

	private void deleteRulesetInternal(RulesetEntity ruleset)
			throws RulesetNotFoundException, RulesetException {
		// Remove all rulesets and rules from this ruleset
		ruleset.getRulesets().clear();
		ruleset.getRules().clear();
		// Remove all references to this ruleset from other rulesets
		rulesetRepository.findAll().forEach(r -> r.getRulesets().remove(ruleset));
		// Remove all references to this ruleset from repositories
		repositoryRepository.findAll().stream()
				.filter(repo -> repo.getRuleset() != null && repo.getRuleset().equals(ruleset))
				.forEach(repo -> {
					repo.setRuleset(getDefaultRuleset());
					repositoryRepository.save(repo);
				});
		repositoryRepository.flush();
		rulesetRepository.delete(ruleset);
	}

	/**
	 * Edits the ruleset whose ID matches that of the given ruleset. Updates the matching ruleset to
	 * use all values of the given ruleset, performing validation to ensure it does not create a
	 * name collision or violate primary and supporting ruleset structure.
	 *
	 * @param rulesetDto dto of ruleset containing new
	 * @throws RulesetNotFoundException if no ruleset with the given ID exists
	 * @throws RulesetException         if a different ruleset with the given name exists or if
	 *                                  designation creates an inheritance conflict
	 */
	public void editRuleset(RulesetDto rulesetDto)
			throws RulesetNotFoundException, RulesetException {
		RulesetEntity ruleset = getRuleset(rulesetDto.getId());
		// Check to avoid changing Provided rulesets
		if (ruleset.getDesignation().equals(RulesetDesignation.PROVIDED)) {
			throw new RulesetException("Cannot modify a Provided Ruleset");
		}
		// Make sure values are not null or empty
		if (StringUtils.isBlank(rulesetDto.getName())
				|| StringUtils.isBlank(rulesetDto.getDescription())) {
			throw new IllegalArgumentException(
					"Please provide a ruleset name and description that are not null or empty.");
		}
		// Make sure designation is not null or provided. Ruleset may be default if the previous was
		// default too
		if (rulesetDto.getDesignation() == null
				|| rulesetDto.getDesignation().equals(RulesetDesignation.PROVIDED)
				|| (rulesetDto.getDesignation().equals(RulesetDesignation.DEFAULT)
						&& !ruleset.getDesignation().equals(RulesetDesignation.DEFAULT))) {
			throw new IllegalArgumentException("Please provide a valid ruleset designation.");
		}

		// Make sure we do not have a name collision
		if (createsNameCollision(rulesetDto.getId(), rulesetDto.getName())) {
			throw new RulesetException(
					"A ruleset with the name \"" + rulesetDto.getName() + "\" already exists.");
		}
		// Make sure that we do not create a supporting ruleset that inherits from primary rulesets
		if (rulesetDto.getDesignation().equals(RulesetDesignation.SUPPORTING)
				&& ruleset.getRulesets().stream()
						.anyMatch(r -> !r.getDesignation().equals(RulesetDesignation.SUPPORTING))) {
			throw new RulesetException(
					"Ruleset cannot be a supporting ruleset if it inherits from a primary ruleset.");
		}

		ruleset.setName(rulesetDto.getName());
		ruleset.setDescription(rulesetDto.getDescription());
		ruleset.setDesignation(rulesetDto.getDesignation());
		// Supporting rulesets always have a blocking level of 'None'
		ruleset.setBlockingLevel(
				rulesetDto.getDesignation().equals(RulesetDesignation.SUPPORTING) ? null
						: rulesetDto.getBlockingLevel());
		rulesetRepository.saveAndFlush(ruleset);
	}

	/**
	 * Sets the rulesets from which the ruleset with the given ID inherits rules. Will only set the
	 * inherited rulesets if there are no problems inheriting any of the rulesets in the given list.
	 *
	 * @param rulesetId           ID of the ruleset to set rules for
	 * @param inheritedRulesetIds IDs of the inherited rulesets to set for the ruleset
	 * @throws RulesetNotFoundException if no ruleset exists for a given ID
	 * @throws RulesetException         if a supporting ruleset tries to inherit from a primary
	 *                                  ruleset
	 */
	public void setInheritedRulesets(long rulesetId, List<Long> inheritedRulesetIds)
			throws RulesetNotFoundException, RulesetException {
		RulesetEntity ruleset = getRuleset(rulesetId);
		// Check that we do not create inheritance on a Provided ruleset
		if (ruleset.getDesignation().equals(RulesetDesignation.PROVIDED)) {
			throw new RulesetException(
					"Cannot have a provided ruleset inherit from any other ruleset.");
		}
		Set<RulesetEntity> inheritedRulesets = new HashSet<>();
		for (Long inheritedRulesetId : inheritedRulesetIds) {
			RulesetEntity inheritedRuleset = getRuleset(inheritedRulesetId);
			// Check that the rulesets are not equal
			if (ruleset.equals(inheritedRuleset)) {
				throw new RulesetException("Cannot add a ruleset to itself.");
			}
			// Check that the inherited ruleset doesn't already contain the ruleset
			if (inheritedRuleset.containsRuleset(ruleset)) {
				throw new RulesetException("Cannot create a circular dependency within a ruleset.");
			}
			inheritedRulesets.add(inheritedRuleset);
		}
		// Check that we do not create a supporting ruleset that inherits from a primary ruleset
		if (ruleset.getDesignation().equals(RulesetDesignation.SUPPORTING)
				&& inheritedRulesets.stream()
						.anyMatch(r -> (r.getDesignation().equals(RulesetDesignation.PRIMARY)
								|| r.getDesignation().equals(RulesetDesignation.DEFAULT)))) {
			throw new RulesetException("Supporting rulesets cannot inherit from primary rulesets.");
		}
		ruleset.setRulesets(inheritedRulesets);

		rulesetRepository.saveAndFlush(ruleset);
	}

	/**
	 * Sets the rules for a ruleset with the given ID. Will only set rules if rules exist for all
	 * rule in the given list of rule IDs.
	 *
	 * @param rulesetId ID of the ruleset to set rules for
	 * @param ruleIds   IDs of the rules to set for the ruleset
	 * @throws RulesetNotFoundException if no ruleset with the given ID exists
	 * @throws RuleNotFoundException    if no rule with any of the given IDs exists
	 */
	public void setRules(long rulesetId, List<Long> ruleIds)
			throws RulesetNotFoundException, RuleNotFoundException {
		RulesetEntity ruleset = getRuleset(rulesetId);
		Set<RuleEntity> rules = new HashSet<>();
		for (Long ruleId : ruleIds) {
			// If any rule is not found, ruleset will not be altered
			RuleEntity rule = ruleService.getRule(ruleId);
			rules.add(rule);
		}
		ruleset.setRules(rules);
		rulesetRepository.saveAndFlush(ruleset);
	}

	/**
	 * Sets the default ruleset as the ruleset with the given ID. If the given ID is -1, removes the
	 * default designation from the current default ruleset, if it exists.
	 *
	 * @param rulesetId ID of the ruleset to set as the default
	 * @return The configured default ruleset, or null if the default ruleset is un-set
	 * @throws RulesetNotFoundException if no ruleset with the given ID exists
	 * @throws RulesetException         if a supporting ruleset is being set as the default
	 */
	public RulesetEntity setDefaultRuleset(long rulesetId)
			throws RulesetNotFoundException, RulesetException {
		if (rulesetId == -1L) {
			// Set current default to primary
			RulesetEntity defaultRuleset = getDefaultRuleset();
			if (defaultRuleset != null) {
				defaultRuleset.setDesignation(RulesetDesignation.PRIMARY);
				rulesetRepository.saveAndFlush(defaultRuleset);
			}
			return null;
		} else {
			// Check that given ruleset is valid
			RulesetEntity ruleset = getRuleset(rulesetId);
			if (ruleset.getDesignation().equals(RulesetDesignation.SUPPORTING) ||
					ruleset.getDesignation().equals(RulesetDesignation.PROVIDED)) {
				throw new RulesetException(
						"Can only set a primary ruleset as the default ruleset.");
			}
			// Set current default to primary
			RulesetEntity defaultRuleset = getDefaultRuleset();
			if (defaultRuleset != null) {
				defaultRuleset.setDesignation(RulesetDesignation.PRIMARY);
				rulesetRepository.save(defaultRuleset);
			}
			// Set given ruleset to default
			ruleset.setDesignation(RulesetDesignation.DEFAULT);
			return rulesetRepository.saveAndFlush(ruleset);
		}
	}

	/**
	 * Remove the rule with the given rule ID from all rulesets, so that the rule can be safely
	 * deleted.
	 *
	 * @param ruleId ID of the rule to be removed from all rulesets
	 * @throws RuleNotFoundException if the rule does not exist
	 * @throws RuleException         if the rule cannot be removed
	 */
	public void removeRuleFromAllRulesets(long ruleId) throws RuleNotFoundException, RuleException {
		RuleEntity rule = ruleService.getRule(ruleId);
		if (rule.toDto().isProvided()) {
			throw new RuleException("Cannot delete a provided rule");
		}
		Collection<RulesetEntity> rulesets = rulesetRepository.findAll();
		rulesets.forEach(ruleset -> ruleset.getRules().remove(rule));
		rulesetRepository.saveAll(rulesets);
		rulesetRepository.flush();
	}

	/**
	 * Imports a ruleset from the given input stream. Assigns the given user as the author for all
	 * rules within the ruleset. This is an all-or-nothing operation. If any rule import fails, no
	 * ruleset will be created and no rules will be imported. Creates a ruleset if no ruleset with
	 * the name in the file exists.
	 *
	 * @param inputStream stream of file containing ruleset to import
	 * @param userName    user to assign as author of new rules
	 * @return the imported ruleset
	 * @throws IllegalArgumentException if the user is null
	 * @throws ModuleNotFoundException  if there is no interpreter associated with the given module
	 * @throws IOException              if an error occurs while handling the input stream
	 * @throws RulesetException         if the rules are invalid or if the ruleset cannot be created
	 */
	public RulesetDto importRuleset(InputStream inputStream, String userName)
			throws IllegalArgumentException, ModuleNotFoundException, IOException,
			RulesetException {
		// Check that user is not null
		if (StringUtils.isBlank(userName)) {
			throw new IllegalArgumentException("User cannot be null.");
		}
		// Convert ruleset to DTO
		RulesetDto rulesetDto = mapper.readValue(inputStream, RulesetDto.class);
		// TODO allow configuration of these options?
		return importOrUpdateRuleset(rulesetDto, userName, ImportOption.UPDATE,
				ImportOption.UPDATE).toDto();
	}

	/**
	 * Exports the ruleset with the given ID to a zip file, containing one file for each type of
	 * rule in the ruleset. Exports all rules in the ruleset, including those inherited from other
	 * rulesets. The zip file is attached to the given response.
	 *
	 * @param id       of the ruleset to export
	 * @param response HTTP response to attach the zip file to
	 * @throws RulesetNotFoundException if no ruleset exists for the given ID
	 * @throws RulesetException         if there are no rules to be exported
	 * @throws IOException              if there is an issue exporting to a stream
	 */
	public void exportRuleset(long id, HttpServletResponse response)
			throws RulesetNotFoundException, RulesetException, IOException {
		RulesetDto rulesetDto = getRuleset(id).toDto();
		if (rulesetDto.isProvided()) {
			throw new RulesetException("Cannot export a Provided Ruleset");
		}
		// Check that there are rules to export
		if (rulesetDto.getNumRules() == 0) {
			throw new RulesetException(
					"Ruleset with name \"" + rulesetDto.getName()
							+ "\" does not contain any rules.");
		}
		String rulesetName = rulesetDto.getName().replaceAll("\\s", "-");
		// Set response headers
		response.setStatus(HttpServletResponse.SC_OK);
		response.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
		response.setHeader(HttpHeaders.CONTENT_DISPOSITION,
				"attachment; filename=\"" + rulesetName + ".json\"");

		OutputStream outputStream = response.getOutputStream();
		InputStream inputStream =
				new ByteArrayInputStream(mapper.writeValueAsString(rulesetDto).getBytes());

		StreamUtils.copy(inputStream, outputStream);

		inputStream.close();
		outputStream.flush();
		outputStream.close();
		response.flushBuffer();
	}

	/**
	 * Gets the ruleset entity whose ID matches the given ID.
	 *
	 * @param id ID of the ruleset to get
	 * @return ruleset entity with the given ID
	 * @throws RulesetNotFoundException if no ruleset with the given ID exists
	 */
	public RulesetEntity getRuleset(long id) throws RulesetNotFoundException {
		Optional<RulesetEntity> ruleset = rulesetRepository.findById(id);
		if (!ruleset.isPresent()) {
			throw new RulesetNotFoundException("No such ruleset exists.");
		}
		return ruleset.get();
	}

	/**
	 * Gets the default ruleset configured for Watchtower.
	 *
	 * @return the default ruleset, or null if no default ruleset is configured
	 */
	public RulesetEntity getDefaultRuleset() {
		return rulesetRepository.findByDesignation(RulesetDesignation.DEFAULT);
	}

	public RulesetEntity getRuleset(String name) throws RulesetNotFoundException {
		RulesetEntity ruleset = rulesetRepository.findByName(name);
		if (ruleset == null) {
			throw new RulesetNotFoundException("No such ruleset exists.");
		}
		return ruleset;
	}

	private boolean createsNameCollision(long id, String name) {
		try {
			RulesetEntity rule = getRuleset(name);
			return rule.getId() != id;
		} catch (RulesetNotFoundException e) {
			return false;
		}
	}

	/**
	 * Register the provided rulesets from the module during startup. This will override all
	 * provided rules, rulesets, and remove deprecated/removed rules and rulesets that were imported
	 * from an earlier version of the module
	 * 
	 * @param moduleName               the name of the module
	 * @param incomingProvidedRulesets the rulesets to import
	 * @return the imported rulesets
	 * @throws ModuleException if any import fails
	 */
	public List<RulesetDto> registerProvidedRulesets(String moduleName,
			List<RulesetDto> incomingProvidedRulesets)
			throws ModuleException {
		List<RulesetDto> updatedRulesets = new ArrayList<RulesetDto>();
		List<RulesetDto> relevantWatchtowerProvidedRulesets =
				getRulesets().stream().filter(
						ruleset -> ruleset.isProvided() && ruleset.getName().startsWith(moduleName))
						.collect(Collectors.toList());
		try {
			for (RulesetDto incomingRulesetDto : incomingProvidedRulesets) {
				// Make sure ruleset is designated properly
				if (!incomingRulesetDto.isProvided()) {
					throw new ModuleException(
							"Trying to register a provided ruleset, but not designated correctly. Module "
									+ moduleName + " ruleset " + incomingRulesetDto.getName());
				}
				List<RuleDto> nonProvidedRules = incomingRulesetDto.getRules().stream()
						.filter(r -> !r.isProvided()).collect(Collectors.toList());
				if (!nonProvidedRules.isEmpty()) {
					throw new ModuleException(
							"Trying to register a provided ruleset, but not all rules are marked provided. Module "
									+ moduleName + " ruleset " + incomingRulesetDto.getName()
									+ " rules: " + Strings.join(nonProvidedRules, ','));
				}

				// Ensure the correct naming convention of the provided ruleset
				if (!incomingRulesetDto.getName().startsWith(moduleName)) {
					incomingRulesetDto.setName(moduleName + " - " + incomingRulesetDto.getName());
				}

				RulesetEntity resultantRuleset = importOrUpdateRuleset(incomingRulesetDto, "system",
						ImportOption.UPDATE, ImportOption.OVERRIDE);
				if (resultantRuleset != null) {
					updatedRulesets.add(resultantRuleset.toDto());
				}
			}
		} catch (RulesetException e) {
			throw new ModuleException(e);
		}

		// Finally, check for orphaned watchtower rules and rulesets (no longer provided)
		removeDeprecatedProvidedRules(updatedRulesets, relevantWatchtowerProvidedRulesets);
		removeDeprecatedProvidedRulesets(updatedRulesets, relevantWatchtowerProvidedRulesets,
				moduleName);
		return updatedRulesets;
	}

	/**
	 * import or update the provided ruleset and its contained rules. It follows this process:
	 * 
	 * <pre>
	 * If the ruleset exists
	 *     If the ruleset should be updated
	 *         The ruleset object will be updated
	 *         For every rule in the ruleset
	 *             If the rule exists
	 *                 If the rule should be updated
	 *                     The rule object will be updated
	 *                 Else
	 *                     Skip
	 *             Else (if the rule is new)
	 *                 Create the rule object
	 *     Else 
	 *         skip
	 * Else (if the ruleset is new)
	 *     Create the new ruleset object
	 *     For every rule in the ruleset
	 *         If the rule exists
	 *             If the rule should be updated
	 *                 The rule object will be updated
	 *             Else
	 *                 Skip
	 *         Else (if the rule is new)
	 *             Create the rule object
	 * Return the new finalized Ruleset object
	 * </pre>
	 * 
	 * @param incomingRulesetDto the ruleset object to import
	 * @param backupAuthorName   the author name to use on rule objects that have no author assigned
	 * @param customOption       the option used during custom rule imports
	 * @param providedOption     the option used during provided rule imports
	 * @return the final ruleset after importing
	 * @throws RulesetException if an import fails
	 */
	private RulesetEntity importOrUpdateRuleset(RulesetDto incomingRulesetDto,
			String backupAuthorName, ImportOption customOption, ImportOption providedOption)
			throws RulesetException {
		RulesetEntity finalRuleset;

		// Look for the ruleset in the watchtower rulesets
		RulesetEntity foundWatchtowerRuleset =
				rulesetRepository.findByName(incomingRulesetDto.getName());
		if (foundWatchtowerRuleset != null) {
			// Existing ruleset known by watchtower, update
			LOG.debug("Found Watchtower Ruleset for name {}, updating",
					incomingRulesetDto.getName());
			finalRuleset = updateExistingRuleset(incomingRulesetDto, backupAuthorName,
					foundWatchtowerRuleset, customOption, providedOption);
		} else {
			// This is a new ruleset, so import it normally
			LOG.debug("No existing Watchtower Ruleset for name {}, importing as new",
					incomingRulesetDto.getName());
			try {
				finalRuleset = importNewRuleset(incomingRulesetDto, backupAuthorName,
						customOption, providedOption);
			} catch (RulesetException e) {
				throw new RulesetException(
						"Failed to import Ruleset: " + incomingRulesetDto.getName(),
						e);
			}
		}
		return finalRuleset;
	}

	private RulesetEntity updateExistingRuleset(RulesetDto incomingRulesetDto, String authorName,
			RulesetEntity foundWatchtowerRuleset, ImportOption customOption,
			ImportOption providedOption) throws RulesetException {
		// ruleset is provided, handle separately
		if (foundWatchtowerRuleset.getDesignation().equals(RulesetDesignation.PROVIDED)) {
			if (providedOption.equals(ImportOption.SKIP)) {
				LOG.debug(
						"Skipping update of provided ruleset {}. Will still update rules in ruleset if configured",
						incomingRulesetDto.getName());
			} else {
				foundWatchtowerRuleset.setBlockingLevel(incomingRulesetDto.getBlockingLevel());
				foundWatchtowerRuleset.setDescription(incomingRulesetDto.getDescription());
			}
		} else if (customOption.equals(ImportOption.SKIP)) {
			// Skip
			LOG.debug(
					"Skipping update of ruleset {}. Will still attempt update of rules in ruleset",
					incomingRulesetDto.getName());
		}
		// ruleset update/override are treated the same
		else {
			foundWatchtowerRuleset.setBlockingLevel(incomingRulesetDto.getBlockingLevel());
			foundWatchtowerRuleset.setDescription(incomingRulesetDto.getDescription());
			foundWatchtowerRuleset.setDesignation(incomingRulesetDto.getDesignation());
		}
		List<RuleEntity> rules =
				ruleService.importRules(incomingRulesetDto.getRules(), authorName, customOption,
						providedOption);
		// Set rules for the ruleset
		foundWatchtowerRuleset.setRules(new HashSet<>(rules));
		return rulesetRepository.saveAndFlush(foundWatchtowerRuleset);
	}

	private RulesetEntity importNewRuleset(RulesetDto rulesetDto, String authorName,
			ImportOption customOption, ImportOption providedOption)
			throws RulesetException {
		// Create ruleset
		RulesetEntity ruleset = new RulesetEntity();
		ruleset.setName(rulesetDto.getName());
		ruleset.setDescription(rulesetDto.getDescription());
		ruleset.setDesignation(rulesetDto.getDesignation() == null ? RulesetDesignation.SUPPORTING
				: rulesetDto.getDesignation());
		ruleset.setBlockingLevel(rulesetDto.getBlockingLevel());
		// Import rules
		List<RuleEntity> rules =
				ruleService.importRules(rulesetDto.getRules(), authorName, customOption,
						providedOption);
		// Set rules for the ruleset
		ruleset.setRules(new HashSet<>(rules));
		ruleset.setRulesets(
				importInheritedRulesets(rulesetDto, authorName, customOption,
						providedOption));
		return rulesetRepository.saveAndFlush(ruleset);
	}

	// Recurse if necessary into the inherited rulesets
	private Set<RulesetEntity> importInheritedRulesets(RulesetDto incomingRuleset,
			String authorName, ImportOption importOption, ImportOption providedOption)
			throws RulesetException {
		Set<RulesetEntity> inherited = new HashSet<>();
		if (incomingRuleset.getRulesets().size() > 0) {
			for (RulesetDto inheritedRuleset : incomingRuleset.getRulesets()) {
				inherited.add(
						importOrUpdateRuleset(inheritedRuleset, authorName, importOption,
								providedOption));
			}
		}
		return inherited;
	}

	private void removeDeprecatedProvidedRules(
			List<RulesetDto> currentProvidedRulesets,
			List<RulesetDto> originalProvidedRulesets) {
		// create lists of original (pre import) rules and new rules for this module
		List<RuleDto> originalRules = originalProvidedRulesets.stream()
				.flatMap(ors -> ors.getRules().stream()).collect(Collectors.toList());
		List<RuleDto> currentRules = currentProvidedRulesets.stream()
				.flatMap(ors -> ors.getRules().stream()).collect(Collectors.toList());

		// compare lists so that any rule in the original list, but not in the new list is deleted
		originalRules.stream().filter(
				or -> currentRules.stream().noneMatch(cr -> cr.getName().equals(or.getName())))
				.forEach(r -> {
					try {
						ruleService.deleteRule(r.getId());
					} catch (RuleNotFoundException e) {
						LOG.warn(
								"Attempting to remove deprecated Provided rule {}, but it wasn't found",
								r.getName());
					}
				});
	}

	private void removeDeprecatedProvidedRulesets(List<RulesetDto> updatedRulesets,
			List<RulesetDto> relevantWatchtowerProvidedRulesets, String moduleName)
			throws ModuleException {
		/*
		 * get all watchtower provided rulesets where the ruleset name fits the naming convention
		 * for this module
		 */
		Map<String, RulesetDto> relevantWatchtowerProvidedRulesetsMap =
				relevantWatchtowerProvidedRulesets.stream()
						.collect(Collectors.toMap(RulesetDto::getName, r -> r));
		updatedRulesets.forEach(r -> relevantWatchtowerProvidedRulesetsMap.remove(r.getName()));

		if (relevantWatchtowerProvidedRulesetsMap.isEmpty()) {
			return;
		}
		LOG.debug("Found {} deprecated rulesets", relevantWatchtowerProvidedRulesetsMap.size());
		for (RulesetDto orphanedRuleset : relevantWatchtowerProvidedRulesetsMap.values()) {
			LOG.debug("Deleting ruleset: {} and all sub-rules", orphanedRuleset.getName());
			RulesetEntity orphanedEntity =
					rulesetRepository.findByName(orphanedRuleset.getName());
			try {
				deleteRulesetInternal(orphanedEntity);
			} catch (RulesetNotFoundException | RulesetException e) {
				throw new ModuleException(
						"Exception while deleting provided, orphaned ruleset: "
								+ orphanedEntity.getName(),
						e);
			}
		}
	}
}
