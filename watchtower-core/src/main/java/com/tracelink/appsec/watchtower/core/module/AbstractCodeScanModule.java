package com.tracelink.appsec.watchtower.core.module;

import java.util.List;

import javax.annotation.PostConstruct;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;

import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.core.rule.RuleEditorService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDesignation;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;

/**
 * The Module is the main implementation for a Watchtower scanner.
 * <p>
 * It contains the necessary information to manage and design rules for the scanner in order to
 * function within Watchtower. It also contains functionality to store rules in the database and
 * perform database migrations. It does not provide any Spring controls. See
 * {@link WatchtowerModule} for that functionality, including JPA and Entity creation.
 *
 * @author mcool
 */
public abstract class AbstractCodeScanModule extends AbstractModule {
	private static final Logger LOG = LoggerFactory.getLogger(AbstractCodeScanModule.class);

	@Autowired
	private ScanRegistrationService scanRegistrationService;

	@Autowired
	private RuleEditorService ruleEditorService;

	@Autowired
	private RulesetService rulesetService;

	@Autowired
	private RuleDesignerService ruleDesignerService;



	/**
	 * The implementation of an {@link ICodeScanner}.
	 * <p>
	 * This scanner will be used to run rules against files and generate a report containing info
	 * about any violations found or errors encountered.
	 *
	 * @return scanner implementation for this module
	 */
	public abstract ICodeScanner getScanner();

	/**
	 * The implementation of the {@link IRuleDesigner}.
	 * <p>
	 * This designer will be used to show this module's Rule Designer User Experience
	 *
	 * @return rule designer implementation for this module
	 */
	public abstract IRuleDesigner getRuleDesigner();

	/**
	 * The implementation of the {@link IRuleEditor}.
	 * <p>
	 * The rule editor is used to show this module's Rule Editor User Experience.
	 *
	 * @return rule editor implementation for this module
	 */
	public abstract IRuleEditor getRuleEditor();

	/**
	 * Allow Modules to provide any rules as {@linkplain RulesetDesignation#PROVIDED} rulesets. On
	 * rule updates, the {@linkplain RulesetService} will update existing rules and remove
	 * no-longer-available rules
	 * <p>
	 * Note that all rulesets will be prefixed by the system with the result of
	 * {@linkplain #getName()} to help identify their origin
	 * 
	 * @return a list of {@linkplain RulesetDesignation#PROVIDED} rulesets, or null/blank if the
	 *         module does not have/support built-in third-party rules
	 */
	public abstract List<RulesetDto> getProvidedRulesets();

	/**
	 * Create the Module, calling each of the abstract methods required and validating their content
	 * as needed
	 */
	@PostConstruct
	protected void buildModule() {
		super.buildModule();
		LOG.info("Registering Code Scanner: {}", getName());
		try {
			scanRegistrationService.registerScanner(getName(), getScanner());
			ruleEditorService.registerRuleEditor(getName(), getRuleEditor());
			if (getRuleDesigner() != null) {
				ruleDesignerService.registerRuleDesigner(getName(), getRuleDesigner());
			}
		} catch (ModuleException e) {
			throw new RuntimeException("Error registering code scanner " + getName());
		}
	}

	/**
	 * Certain processes must occur after all modules have been loaded. This method handles those
	 * cases.
	 */
	@EventListener(classes = ContextRefreshedEvent.class)
	public void afterModulesLoaded() {
		try {
			List<RulesetDto> providedRulesets = getProvidedRulesets();
			if (providedRulesets != null) {
				LOG.info("Importing Provided rules for {} Starting", getName());
				rulesetService.registerProvidedRulesets(getName(), providedRulesets);
				LOG.info("Importing Provided rules for {} Complete", getName());
			}
		} catch (ModuleException e) {
			throw new RuntimeException(
					"Error configuring scanner " + getName() + " after all modules loaded", e);
		}
	}
}
