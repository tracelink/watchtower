package com.tracelink.appsec.watchtower.core.ruleset;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.servlet.http.HttpServletResponse;
import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.util.StreamUtils;

import com.tracelink.appsec.watchtower.core.auth.model.UserEntity;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetException;
import com.tracelink.appsec.watchtower.core.exception.rule.RulesetNotFoundException;
import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.interpreter.IRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.module.interpreter.RulesetInterpreterException;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleEntity;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.scm.RepositoryRepository;

/**
 * Handles logic to retrieve and edit rulesets.
 *
 * @author mcool
 */
@Service
public class RulesetService {

	private RulesetRepository rulesetRepository;
	private RuleService ruleService;
	private RepositoryRepository repositoryRepository;

	/**
	 * Map from module name to ruleset interpreter
	 */
	private Map<String, IRulesetInterpreter> interpreterMap =
			new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

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
	}

	/**
	 * Registers a ruleset interpreter with this service to be used for ruleset import and export.
	 *
	 * @param module      the module name
	 * @param interpreter the ruleset interpreter
	 * @throws IllegalArgumentException if module is blank or interpreter is null
	 * @throws ModuleException          if interpreter already exists for the given module
	 */
	public void registerInterpreter(String module, IRulesetInterpreter interpreter)
			throws IllegalArgumentException, ModuleException {
		if (StringUtils.isBlank(module) || interpreter == null) {
			throw new IllegalArgumentException(
					"Module name and ruleset interpreter cannot be null.");
		}
		if (interpreterMap.containsKey(module)) {
			throw new ModuleException(
					"A ruleset interpreter for the given module already exists: " + module);
		}
		interpreterMap.put(module, interpreter);
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
			RulesetDesignation designation)
			throws RulesetException {
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
		try {
			getRuleset(name);
		} catch (RulesetNotFoundException e) {
			RulesetEntity ruleset = new RulesetEntity();
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
		// Make sure designation is not null or default
		if (rulesetDto.getDesignation() == null
				|| rulesetDto.getDesignation().equals(RulesetDesignation.DEFAULT)) {
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
						.anyMatch(r -> !r.getDesignation().equals(RulesetDesignation.SUPPORTING))) {
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
	 * @throws RulesetNotFoundException if no ruleset with the given ID exists
	 * @throws RulesetException         if a supporting ruleset is being set as the default
	 */
	public void setDefaultRuleset(long rulesetId)
			throws RulesetNotFoundException, RulesetException {
		if (rulesetId == -1L) {
			// Set current default to primary
			RulesetEntity defaultRuleset = getDefaultRuleset();
			if (defaultRuleset != null) {
				defaultRuleset.setDesignation(RulesetDesignation.PRIMARY);
				rulesetRepository.saveAndFlush(defaultRuleset);
			}
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
			rulesetRepository.saveAndFlush(ruleset);
		}
	}

	/**
	 * Remove the rule with the given rule ID from all rulesets, so that the rule can be safely
	 * deleted.
	 *
	 * @param ruleId ID of the rule to be removed from all rulesets
	 * @throws RuleNotFoundException if the rule does not exist
	 */
	public void removeRuleFromAllRulesets(long ruleId) throws RuleNotFoundException {
		RuleEntity rule = ruleService.getRule(ruleId);
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
	 * @param module      module associated with the ruleset interpreter to use for import
	 * @param inputStream stream of file containing ruleset to import
	 * @param user        user to assign as author of new rules
	 * @throws IllegalArgumentException    if the user is null
	 * @throws ModuleNotFoundException     if there is no interpreter associated with the given
	 *                                     module
	 * @throws IOException                 if an error occurs while handling the input stream
	 * @throws RulesetInterpreterException if the ruleset cannot be imported
	 * @throws RulesetException            if the rules are invalid or if the ruleset cannot be
	 *                                     created
	 */
	public void importRuleset(String module, InputStream inputStream, UserEntity user)
			throws IllegalArgumentException, ModuleNotFoundException, IOException,
			RulesetInterpreterException, RulesetException {
		// Check that user is not null
		if (user == null) {
			throw new IllegalArgumentException("User cannot be null.");
		}
		// Convert ruleset to DTO
		RulesetDto rulesetDto = getRulesetInterpreter(module).importRuleset(inputStream);
		importRulesetInternal(rulesetDto, user.getUsername());
	}

	private void importRulesetInternal(RulesetDto rulesetDto, String authorName)
			throws RulesetException, RulesetInterpreterException {
		// Validate rules
		validateRules(rulesetDto.getRules());
		// Create ruleset if it does not already exist
		RulesetEntity ruleset = rulesetRepository.findByName(rulesetDto.getName());
		if (ruleset == null) {
			ruleset = createRuleset(rulesetDto.getName(), rulesetDto.getDescription(),
					RulesetDesignation.SUPPORTING);
		}

		// Import rules
		List<RuleEntity> rules = ruleService.importRules(rulesetDto.getRules(), authorName);
		// Set rules for the ruleset
		ruleset.getRules().addAll(rules);
		rulesetRepository.saveAndFlush(ruleset);
	}

	/**
	 * Exports the ruleset with the given ID to a zip file, containing one file for each type of
	 * rule in the ruleset. Exports all rules in the ruleset, including those inherited from other
	 * rulesets. The zip file is attached to the given response.
	 *
	 * @param id       of the ruleset to export
	 * @param response HTTP response to attach the zip file to
	 * @throws RulesetNotFoundException    if no ruleset exists for the given ID
	 * @throws RulesetException            if there are no rules to be exported
	 * @throws IOException                 if there is an issue exporting to a stream
	 * @throws RulesetInterpreterException if there is an issue exporting the ruleset from the
	 *                                     interpreter
	 */
	public void exportRuleset(long id, HttpServletResponse response)
			throws RulesetNotFoundException, RulesetException, IOException,
			RulesetInterpreterException {
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
		response.setHeader(HttpHeaders.CONTENT_TYPE, "application/zip");
		response.setHeader(HttpHeaders.CONTENT_DISPOSITION,
				"attachment; filename=\"" + rulesetName + ".zip\"");

		ZipOutputStream outputStream = new ZipOutputStream(response.getOutputStream());

		for (Map.Entry<String, IRulesetInterpreter> interpreterEntry : interpreterMap.entrySet()) {
			String fileName =
					rulesetName + "-" + interpreterEntry.getKey() + "."
							+ interpreterEntry.getValue().getExtension();
			InputStream inputStream = interpreterEntry.getValue().exportRuleset(rulesetDto);
			// There are no rules for this interpreter in the ruleset, skip to next interpreter
			if (inputStream == null) {
				continue;
			}
			// Create and write zip entry
			ZipEntry zipEntry = new ZipEntry(fileName);
			zipEntry.setSize(inputStream.available());
			outputStream.putNextEntry(zipEntry);
			StreamUtils.copy(inputStream, outputStream);
			inputStream.close();
			outputStream.closeEntry();
		}
		outputStream.finish();
		outputStream.flush();
		outputStream.close();
		response.flushBuffer();
	}

	/**
	 * Given a ruleType/Module name, provide an input stream that allows the example ruleset to be
	 * downloaded
	 * 
	 * @param ruleType the type of the module/rule
	 * @return an inputStream of the example ruleset, or null if not defined
	 * @throws ModuleNotFoundException     if the Module is unknown
	 * @throws IOException                 if the example ruleset cannot be exported or a streaming
	 *                                     error occurs
	 * @throws RulesetInterpreterException if the example ruleset cannot be exported
	 */
	public InputStreamResource downloadExampleRuleset(String ruleType)
			throws ModuleNotFoundException, IOException, RulesetInterpreterException {
		IRulesetInterpreter interpreter = getRulesetInterpreter(ruleType);
		InputStream is = interpreter.exportExampleRuleset();
		if (is == null) {
			return null;
		}
		return new InputStreamResource(is) {
			@Override
			public String getFilename() {
				return ruleType + "." + interpreter.getExtension();
			}

			@Override
			public long contentLength() throws IOException {
				// A content length < 0 forces the Response to stream the data without checking its
				// length which would require re-reading the stream and causes an exception
				return -1L;
			}
		};
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

	private <T extends RuleDto> void validateRules(Set<T> ruleDtos) throws RulesetException {
		ValidatorFactory validatorFactory = Validation.buildDefaultValidatorFactory();
		Validator validator = validatorFactory.getValidator();
		// Validate fields of the rule
		for (T ruleDto : ruleDtos) {
			Set<ConstraintViolation<T>> violations = validator.validate(ruleDto);
			for (ConstraintViolation<T> violation : violations) {
				String property = violation.getPropertyPath().toString();
				if (!"author".equals(property)) {
					throw new RulesetException(
							"The rule with the name \"" + ruleDto.getName() + "\" is invalid: "
									+ violation
											.getMessage());
				}
			}
		}
		// Make sure rules do not already exist with the given names
		for (T ruleDto : ruleDtos) {
			RuleEntity rule = ruleService.getRule(ruleDto.getName());
			if (rule != null) {
				// Fail if we find a rule
				throw new RulesetException(
						"A rule with the name \"" + ruleDto.getName() + "\" already exists.");
			}
		}
	}

	private IRulesetInterpreter getRulesetInterpreter(String interpreter)
			throws ModuleNotFoundException {
		if (!interpreterMap.containsKey(interpreter)) {
			throw new ModuleNotFoundException(
					"No ruleset interpreter exists for the given type: " + interpreter);
		}
		return interpreterMap.get(interpreter);
	}

	public void registerProvidedRulesets(String moduleName,
			List<RulesetDto> incomingProvidedRulesets)
			throws ModuleException {
		/*
		 * get all watchtower provided rulesets where the ruleset name fits the naming convention
		 * for this module
		 */
		Map<String, RulesetDto> relevantWatchtowerProvidedRulesets =
				getRulesets().stream().filter(
						ruleset -> ruleset.isProvided() && ruleset.getName().startsWith(moduleName))
						.collect(Collectors.toMap(RulesetDto::getName, r -> r));

		for (RulesetDto incomingRulesetDto : incomingProvidedRulesets) {
			// Make sure ruleset is designated properly
			if (!incomingRulesetDto.isProvided()) {
				throw new ModuleException(
						"Trying to register a provided ruleset, but not designated correctly. Module "
								+ moduleName + " ruleset " + incomingRulesetDto.getName());
			}

			// Ensure the correct naming convention of the provided ruleset
			if (!incomingRulesetDto.getName().startsWith(moduleName)) {
				incomingRulesetDto.setName(moduleName + " - " + incomingRulesetDto.getName());
			}

			// Look for the provided ruleset in the watchtower rulesets, remove it if found
			RulesetDto foundWatchtowerRuleset =
					relevantWatchtowerProvidedRulesets.remove(incomingRulesetDto.getName());

			if (foundWatchtowerRuleset != null) {
				// existing ruleset known by watchtower, update
				updateExistingProvidedRuleset(incomingRulesetDto, foundWatchtowerRuleset);
			} else {
				// This is a new ruleset, so import it normally
				try {
					importRulesetInternal(incomingRulesetDto, "system");
				} catch (RulesetException | RulesetInterpreterException e) {
					throw new ModuleException(
							"Failed to import Provided Ruleset: " + incomingRulesetDto.getName(),
							e);
				}
			}
		}
		// Finally, check for orphaned watchtower rulesets (no longer provided)
		removeDeprecatedProvidedRulesets(relevantWatchtowerProvidedRulesets);
	}

	private void updateExistingProvidedRuleset(RulesetDto incomingRulesetDto,
			RulesetDto foundWatchtowerRuleset) throws ModuleException {
		RulesetEntity watchtowerRuleset =
				rulesetRepository.findByName(foundWatchtowerRuleset.getName());
		// update the ruleset with the new values, if they exist
		watchtowerRuleset.setBlockingLevel(incomingRulesetDto.getBlockingLevel());
		watchtowerRuleset.setDescription(incomingRulesetDto.getDescription());

		try {
			// validate the new rules to make sure they conform as well
			validateRules(incomingRulesetDto.getRules());
		} catch (RulesetException e) {
			throw new ModuleException("Rule validation failed for new provided ruleset rules", e);
		}
		Set<RuleEntity> newRulesetRules =
				updateRulesInProvidedRuleset(incomingRulesetDto.getRules(),
						foundWatchtowerRuleset.getRules());
		// update the watchtower ruleset and save
		watchtowerRuleset.setRules(newRulesetRules);
		rulesetRepository.saveAndFlush(watchtowerRuleset);
	}

	private Set<RuleEntity> updateRulesInProvidedRuleset(Set<RuleDto> incomingRulesetRules,
			Set<RuleDto> foundWatchtowerRulesetRules) throws ModuleException {
		/*
		 * this will track all rules from the incoming provided ruleset that we save
		 */
		Set<RuleEntity> newRulesetRules = new HashSet<RuleEntity>();

		// now work on updating rules inside the new provided ruleset
		for (RuleDto incomingRule : incomingRulesetRules) {
			// this is do-able because the RuleDto has a comparator implementation
			if (foundWatchtowerRulesetRules.contains(incomingRule)) {
				/*
				 * there's a matching Watchtower Rule in the found Ruleset for this incoming rule,
				 * so update
				 */
				RuleEntity newRule = incomingRule.toEntity();
				RuleEntity existingRule = ruleService.getRule(incomingRule.getName());
				/*
				 * take the id from the existing rule and attach it to the new rule to update the
				 * reference
				 */
				newRule.setId(existingRule.getId());
				newRule = ruleService.saveRule(newRule);
				newRulesetRules.add(newRule);
				// this is do-able because the RuleDto has a comparator implementation
				foundWatchtowerRulesetRules.remove(incomingRule);
			} else {
				// this is a new rule to watchtower, add it to the ruleset
				RuleEntity newRule = incomingRule.toEntity();
				newRule = ruleService.saveRule(newRule);
				newRulesetRules.add(newRule);
			}
		}
		// Check that the original watchtower rules have all been found/updated
		if (!foundWatchtowerRulesetRules.isEmpty()) {
			// There are orphaned rules, so delete them
			for (RuleDto leftoverRule : foundWatchtowerRulesetRules) {
				try {
					removeRuleFromAllRulesets(leftoverRule.getId());
				} catch (RuleNotFoundException e) {
					throw new ModuleException(
							"Failed to remove orphaned rule during Provided ruleset registration. Rule: "
									+ leftoverRule.getName(),
							e);
				}
			}
		}
		return newRulesetRules;
	}

	private void removeDeprecatedProvidedRulesets(
			Map<String, RulesetDto> relevantWatchtowerProvidedRulesets) throws ModuleException {
		if (relevantWatchtowerProvidedRulesets.isEmpty()) {
			return;
		}
		for (RulesetDto orphanedRuleset : relevantWatchtowerProvidedRulesets.values()) {
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
