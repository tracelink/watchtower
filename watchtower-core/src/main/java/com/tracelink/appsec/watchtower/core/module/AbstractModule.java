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

import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.auth.service.AuthConfigurationService;

public abstract class AbstractModule {
	private static final Logger LOG = LoggerFactory.getLogger(AbstractModule.class);

	@Autowired
	private Flyway flyway;

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
	 * Allow Modules to provide additional privileges they utilize to be added to the main set of
	 * privileges in Watchtower
	 * 
	 * @return the list of privileges used in the Module, or null if there are none
	 */
	public abstract List<PrivilegeEntity> getModulePrivileges();

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

		LOG.info("BUILDING MODULE: {}", name);

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
		try {
			List<PrivilegeEntity> privileges = getModulePrivileges();
			if (privileges != null) {
				for (PrivilegeEntity privilege : privileges) {
					authService.registerNewPrivilege(getName(), privilege.getCategory(),
							privilege.getName(), privilege.getDescription());
				}
			}
		} catch (ModuleException e) {
			throw new RuntimeException("Error registering module " + getName());
		}
	}
}
