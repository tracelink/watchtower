package com.tracelink.appsec.module.pmd.service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.module.pmd.model.PMDCustomRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDPropertyDto;
import com.tracelink.appsec.module.pmd.model.PMDPropertyEntity;
import com.tracelink.appsec.module.pmd.model.PMDProvidedRuleDto;
import com.tracelink.appsec.module.pmd.model.PMDRuleEntity;
import com.tracelink.appsec.module.pmd.repository.PMDRuleRepository;
import com.tracelink.appsec.watchtower.core.exception.rule.RuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerException;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RuleException;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;

import net.sourceforge.pmd.lang.Language;
import net.sourceforge.pmd.lang.LanguageRegistry;
import net.sourceforge.pmd.lang.rule.Rule;
import net.sourceforge.pmd.lang.rule.RuleSet;
import net.sourceforge.pmd.lang.rule.RuleSetLoader;
import net.sourceforge.pmd.lang.rule.xpath.XPathRule;
import net.sourceforge.pmd.lang.rule.xpath.XPathVersion;
import net.sourceforge.pmd.properties.PropertyDescriptor;

/**
 * Handles logic to retrieve and edit PMD rules.
 *
 * @author mcool
 */
@Service
public class PMDRuleService {

	@Autowired(required = false)
	private com.tracelink.appsec.watchtower.core.rule.RuleService coreRuleService;

	private void invalidateRuleCache() {
		if (coreRuleService != null) {
			coreRuleService.invalidateRuleCache();
		}
	}

	private final PMDRuleRepository ruleRepository;
	private Map<PMDLanguageSupport, List<RulesetDto>> providedRulesetMap;
	private Map<String, PMDProvidedRuleDto> providedRulesMap;
	private Map<String, Rule> pmdOriginalRulesMap;

	/**
	 * Creates and instance of this service with a {@link PMDRuleRepository}.
	 *
	 * @param ruleRepository repository to interact with the database
	 */
	public PMDRuleService(@Autowired PMDRuleRepository ruleRepository) {
		this.ruleRepository = ruleRepository;
	}

	/**
	 * Gets the PMD rule with the given ID.
	 *
	 * @param id ID of the rule to retrieve
	 * @return PMD rule with the given ID
	 * @throws RuleNotFoundException if no PMD rule with the given id exists
	 */
	public PMDRuleEntity getRule(long id) throws RuleNotFoundException {
		Optional<PMDRuleEntity> rule = ruleRepository.findById(id);
		if (!rule.isPresent()) {
			throw new RuleNotFoundException("No such PMD rule exists.");
		}
		return rule.get();
	}

	/**
	 * Edits the PMD rule with the same ID as the given {@link PMDCustomRuleDto}. Updates select
	 * fields of the rule with values from the DTO.
	 *
	 * @param dto rule DTO whose fields will be used to edit the PMD rule
	 * @throws RuleNotFoundException if no PMD rule exists with the same ID as the given DTO
	 */
	public void editRule(RuleDto dto) throws RuleNotFoundException {
		PMDRuleEntity rule = getRule(dto.getId());
		if (rule.isProvided()) {
			rule.setPriority(dto.getPriority());
		} else {
			PMDCustomRuleDto custom = (PMDCustomRuleDto) dto;
			// Set inherited fields
			rule.setName(custom.getName());
			rule.setMessage(custom.getMessage());
			rule.setExternalUrl(custom.getExternalUrl());
			rule.setPriority(custom.getPriority());
			// Set PMD properties
			for (PMDPropertyEntity propertyEntity : rule.getProperties()) {
				for (PMDPropertyDto propertyDto : custom.getProperties()) {
					if (propertyEntity.getId() == propertyDto.getId()) {
						propertyEntity.setName(propertyDto.getName());
						propertyEntity.setValue(propertyDto.getValue());
					}
				}
			}
		}
		rule.refreshRevision();
		ruleRepository.saveAndFlush(rule);
		invalidateRuleCache();
	}

	/**
	 * Save the supplied DTO as a PMD Rule Entity
	 *
	 * @param dto the rule data to save
	 * @throws RuleDesignerException if the rule name already exists
	 */
	public void saveNewRule(PMDCustomRuleDto dto) throws RuleDesignerException {
		if (ruleRepository.findByName(dto.getName()) != null) {
			throw new RuleDesignerException(
					"Rule with the name " + dto.getName() + " already exists");
		}

		if (PMDLanguageSupport.getSupportedLanguageNames().contains(dto.getParserLanguage())) {
			dto.setParserLanguage(dto.getParserLanguage().toLowerCase());
		} else {
			throw new RuleDesignerException(
					"Please select a supported language: " + String
							.join(", ", PMDLanguageSupport.getSupportedLanguageNames()));
		}
		PMDRuleEntity entity = dto.toEntity();
		entity.setAuthor(dto.getAuthor());
		ruleRepository.saveAndFlush(entity);
		invalidateRuleCache();
	}

	public Map<PMDLanguageSupport, List<RulesetDto>> getPMDProvidedRulesetsMap() {
		if (providedRulesetMap == null) {
			makePMDProvidedRulesMaps();
		}
		return providedRulesetMap;
	}

	public Map<String, PMDProvidedRuleDto> getPMDProvidedRulesMap() {
		if (providedRulesMap == null) {
			makePMDProvidedRulesMaps();
		}
		return providedRulesMap;
	}

	private Map<String, Rule> getPMDOriginalRulesMap() {
		if (pmdOriginalRulesMap == null) {
			makePMDProvidedRulesMaps();
		}
		return pmdOriginalRulesMap;
	}

	private void makePMDProvidedRulesMaps() {
		Map<PMDLanguageSupport, List<RulesetDto>> providedRulesets = new TreeMap<>();
		Map<String, PMDProvidedRuleDto> providedRules = new HashMap<>();
		Map<String, Rule> originalRules = new HashMap<String, Rule>();
		RuleSetLoader rsl = new RuleSetLoader();
		List<RuleSet> rsList = rsl.getStandardRuleSets();
		for (RuleSet rs : rsList) {
			// if the rules in this ruleset match a supported language
			if (rs.getRules().size() > 0) {
				Optional<PMDLanguageSupport> support = PMDLanguageSupport
						.getPMDLanguageSupport(rs.getRules().iterator().next().getLanguage());
				if (support.isPresent()) {
					PMDLanguageSupport languageSupport = support.get();
					RulesetDto watchtowerRuleset = new RulesetDto();
					watchtowerRuleset.setBlockingLevel(RulePriority.LOW);
					watchtowerRuleset.setDescription(rs.getDescription());
					watchtowerRuleset.setDesignation(RulesetDesignation.PROVIDED);
					watchtowerRuleset
							.setName(languageSupport.getLanguageName() + " " + rs.getName());
					rs.getRules().forEach(rule -> {
						// Create PMD Provided Rule
						PMDProvidedRuleDto dto = new PMDProvidedRuleDto();
						dto.setName(rule.getName());
						dto.setMessage(rule.getMessage());
						dto.setPriority(RulePriority.LOW);
						dto.setExternalUrl(rule.getExternalInfoUrl());
						// attach to the watchtowerRuleset
						watchtowerRuleset.getRules().add(dto);
						// add to the rules listing
						providedRules.put(dto.getName(), dto);
						originalRules.put(rule.getName(), rule);
					});
					List<RulesetDto> rulesetsForLanguage = providedRulesets.get(languageSupport);
					if (rulesetsForLanguage == null) {
						rulesetsForLanguage = new ArrayList<>();
						providedRulesets.put(languageSupport, rulesetsForLanguage);
					}
					rulesetsForLanguage.add(watchtowerRuleset);
				}
			}
		}
		providedRulesetMap = providedRulesets;
		providedRulesMap = providedRules;
		pmdOriginalRulesMap = originalRules;
	}

	/**
	 * Method to create/find the PMD rule for the given {@linkplain RuleDto}. Will consult with the
	 * internal ruleset or create the custom definition as needed
	 * 
	 * @param ruleDto the Watchtower rule to use
	 * @return the PMD rule created for this Watchtower rule
	 * @throws RuleException         if the rule is custom but cannot be created
	 * @throws RuleNotFoundException if the rule is provided but cannot be found
	 */
	public Rule makeRuleFromDto(RuleDto ruleDto) throws RuleException, RuleNotFoundException {
		Rule pmdRule;
		if (ruleDto.isProvided()) {
			PMDProvidedRuleDto provided = (PMDProvidedRuleDto) ruleDto;
			pmdRule = getPMDOriginalRulesMap().get(provided.getName());
			if (pmdRule == null) {
				throw new RuleNotFoundException("Unknown Provided Rule " + provided.getName());
			}
		} else {
			PMDCustomRuleDto custom = (PMDCustomRuleDto) ruleDto;
			try {
				// PMD 7 removed net.sourceforge.pmd.rules.RuleBuilder entirely; the equivalent
				// of building a rule from a class name is now direct reflection plus the Rule
				// interface's own setters (the same fields RuleBuilder used to configure) -
				// except for XPathRule, which needs special handling; see instantiateRule.
				Class<?> ruleImplClass = Class.forName(custom.getRuleClass());
				pmdRule = instantiateRule(ruleImplClass, custom);
				pmdRule.setName(custom.getName());
				Language language = LanguageRegistry.PMD.getLanguageById(custom.getParserLanguage());
				pmdRule.setLanguage(language);
				pmdRule.setPriority(
						net.sourceforge.pmd.lang.rule.RulePriority.valueOf(
								custom.getPriority().getPriority()));
				pmdRule.setMessage(custom.getMessage());
				pmdRule.setExternalInfoUrl(custom.getExternalUrl());
				pmdRule.setDescription(custom.getMessage());
				custom.getProperties().stream()
						.filter(prop -> (pmdRule.getPropertyDescriptor(prop.getName()) != null))
						.forEach(prop -> {
							PropertyDescriptor desc =
									pmdRule.getPropertyDescriptor(prop.getName());
							pmdRule.setProperty(desc, desc.serializer().fromString(prop.getValue()));
						});
			} catch (ReflectiveOperationException e) {
				throw new RuleException(
						"Cannot create custom PMD rule " + custom.getName(), e);
			}
		}
		return pmdRule;
	}

	/**
	 * Constructs an instance of the given rule class for the given custom rule DTO.
	 *
	 * <p>
	 * Handles one special case: {@link XPathRule} dropped its no-arg constructor and
	 * {@code setXPath(String)} method in PMD 7 in favor of an immutable
	 * {@code XPathRule(XPathVersion, String)} constructor - the XPath expression must be
	 * supplied up front. Since {@link com.tracelink.appsec.module.pmd.controller.PMDDesignerController}
	 * always creates custom rules as {@code XPathRule} with the expression stored as a property
	 * named {@code "xpath"}, that property is pulled out here and passed to the constructor
	 * instead of going through the generic reflection + property-setting path below (which only
	 * works for rule classes with a plain no-arg constructor, e.g. Watchtower's own bundled
	 * custom rules like {@code RestrictNodesUnderProject}).
	 *
	 * @param ruleImplClass the rule's class, already resolved via {@code Class.forName}
	 * @param custom        the custom rule DTO, for its properties
	 * @return a new instance of the rule
	 * @throws ReflectiveOperationException if the class can't be instantiated
	 * @throws RuleException                if an {@code XPathRule} is missing its xpath property
	 */
	private Rule instantiateRule(Class<?> ruleImplClass, PMDCustomRuleDto custom)
			throws ReflectiveOperationException, RuleException {
		if (XPathRule.class.equals(ruleImplClass)) {
			String xpathExpression = custom.getProperties().stream()
					.filter(prop -> "xpath".equals(prop.getName()))
					.map(PMDPropertyDto::getValue)
					.findFirst()
					.orElseThrow(() -> new RuleException(
							"Cannot create custom PMD rule " + custom.getName()
									+ ": XPathRule is missing its 'xpath' property"));
			return new XPathRule(XPathVersion.DEFAULT, xpathExpression);
		}
		return (Rule) ruleImplClass.getDeclaredConstructor().newInstance();
	}
}
