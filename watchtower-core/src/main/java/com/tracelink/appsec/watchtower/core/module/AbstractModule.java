package com.tracelink.appsec.watchtower.core.module;

import java.util.List;

import javax.annotation.PostConstruct;

import org.apache.commons.lang3.StringUtils;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.Location;
import org.flywaydb.core.api.configuration.ClassicConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;

import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.service.AuthConfigurationService;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.interpreter.IRulesetInterpreter;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
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
public abstract class AbstractModule {
	private static final Logger LOG = LoggerFactory.getLogger(AbstractModule.class);

	@Autowired
	private Flyway flyway;

	@Autowired
	private ScanRegistrationService scanRegistrationService;

	@Autowired
	private RuleEditorService ruleEditorService;

	@Autowired
	private RulesetService rulesetService;

	@Autowired
	private RuleDesignerService ruleDesignerService;

	@Autowired
	private AuthConfigurationService authService;

	/**
	 * The name of the module.
	 * <p>
	 * This value is important, as it will be used throughout Watchtower to distinguish between
	 * different modules. The name must not contain whitespace in order to ensure that all
	 * functionality works as expected. This should be considered a human readable display name.
	 * <p>
	 * e.g. "Demo" module or "SpecialDemo" module
	 *
	 * @return name of the module
	 */
	public abstract String getName();

	/**
	 * The name of the schema history table used for this module's Flyway migrations.
	 * <p>
	 * In general, it is a good practice to have the schema history table named after the module.
	 * Since all modules and Watchtower core share the same schema, it is important that each module
	 * has a unique table and that the tables do not conflict with the "flyway_schema_history" table
	 * used by Watchtower core.
	 * <p>
	 * e.g. "demo_schema_history" for a module named "Demo"
	 *
	 * @return schema history table name
	 */
	public abstract String getSchemaHistoryTable();

	/**
	 * The Flyway migration scripts folder.
	 * <p>
	 * In general, it is a good practice to have the migration location be a folder in the project
	 * named after the plugin. During multiple plugin loads, depending on the ordering of the loads,
	 * it is possible to have one plugin find the migration location of another plugin and the app
	 * will not start correctly.
	 * <p>
	 * e.g. "/db/demo" to get the folder /src/main/resources/db/demo/{V001__[name].sql,
	 * V002__[name]...}
	 *
	 * @return the location of the migrations folder in the resources directory
	 */
	public abstract String getMigrationsLocation();

	/**
	 * The implementation of an {@link IScanner}.
	 * <p>
	 * This scanner will be used to run rules against files and generate a report containing info
	 * about any violations found or errors encountered.
	 *
	 * @return scanner implementation for this module
	 */
	public abstract IScanner getScanner();

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
	 * The implementation of an {@link IRulesetInterpreter}.
	 * <p>
	 * This ruleset interpreter will be used to translate between rulesets (and rules) stored in the
	 * database, and their file formats, such as XML or JSON. This is used both to import and export
	 * rules, but also to write rules to temporary files for scanning.
	 *
	 * @return ruleset interpreter implementation for this module
	 */
	public abstract IRulesetInterpreter getInterpreter();


	/**
	 * Allow Modules to provide additional privileges they utilize to be added to the main set of
	 * privileges in Watchtower
	 * 
	 * @return the list of privileges used in the Module, or null if there are none
	 */
	public abstract List<PrivilegeEntity> getModulePrivileges();

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
		String name = getName();
		if (StringUtils.isEmpty(name) || StringUtils.containsWhitespace(name)) {
			throw new IllegalStateException("Module " + getClass().toString()
					+ " could not be created as it does not have a valid name. Please provide a nonempty string that does not contain whitespace.");
		}

		LOG.info("BUILDING SCANNER: " + name);

		ClassicConfiguration compConfig = new ClassicConfiguration(flyway.getConfiguration());

		// set the correct schema table
		compConfig.setTable(getSchemaHistoryTable());

		// set the correct location
		compConfig.setLocations(new Location(getMigrationsLocation()));

		// baseline on migrate
		compConfig.setBaselineOnMigrate(true);
		compConfig.setBaselineVersionAsString("0");

		// migrate
		Flyway.configure().configuration(compConfig).load().migrate();

		LOG.info("Registering Scanner: " + name);
		try {
			scanRegistrationService.registerScanner(getName(), getScanner());
			ruleEditorService.registerRuleEditor(getName(), getRuleEditor());
			rulesetService.registerInterpreter(getName(), getInterpreter());
			if (getRuleDesigner() != null) {
				ruleDesignerService.registerRuleDesigner(getName(), getRuleDesigner());
			}
			List<PrivilegeEntity> privileges = getModulePrivileges();
			if (privileges != null) {
				for (PrivilegeEntity privilege : privileges) {
					authService.registerNewPrivilege(getName(), privilege.getCategory(),
							privilege.getName(), privilege.getDescription());
				}
			}
		} catch (ModuleException e) {
			throw new RuntimeException("Error registering scanner " + name, e);
		}
	}

	@EventListener
	public void onApplicationEvent(ContextRefreshedEvent event) throws ModuleException {
		if (getProvidedRulesets() != null) {
			rulesetService.registerProvidedRulesets(getName(), getProvidedRulesets());
		}
	}
}
