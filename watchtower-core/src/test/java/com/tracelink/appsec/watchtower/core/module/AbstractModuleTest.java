package com.tracelink.appsec.watchtower.core.module;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.List;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.core.rule.RuleEditorService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;

@ExtendWith({SpringExtension.class, MockitoExtension.class})
@MockitoSettings(strictness = Strictness.LENIENT)
public class AbstractModuleTest {
	private Flyway flyway;

	@MockitoBean
	private RulesetService mockRulesetService;

	@MockitoBean
	private RuleEditorService mockRuleEditorService;

	@MockitoBean
	private RuleDesignerService mockRuleDesignerService;

	@MockitoBean
	private ScanRegistrationService mockScanRegistrationService;

	@Mock
	private ICodeScanner mockScanner;

	@Mock
	private IRuleDesigner mockDesigner;

	@Mock
	private IRuleEditor mockRuleManager;

	private String moduleName = "Mock";
	private String migrations = "/testdb";
	private String schemaLocation = "mock_schema_history";

	/*
	 * I feel like I need to explain myself here: We are using field injection exclusively in the
	 * Plugin abstraction so to make the plugin implementation as easy as possible. No constructors
	 * with odd, internal services that every plugin needs to include, instead this autowiring
	 * happens behind the scenes at the core abstraction layer(s). So in order to test this
	 * "not best practice" we have to commit a different cardinal sin and manually inject the mocks
	 * during testing using Reflection
	 */
	private AbstractCodeScanModule injectMocks(AbstractCodeScanModule module) {
		ReflectionTestUtils.setField(module, "flyway", flyway);
		ReflectionTestUtils.setField(module, "ruleEditorService", mockRuleEditorService);
		ReflectionTestUtils.setField(module, "rulesetService", mockRulesetService);
		ReflectionTestUtils.setField(module, "ruleDesignerService", mockRuleDesignerService);
		ReflectionTestUtils.setField(module, "scanRegistrationService",
				mockScanRegistrationService);
		return module;
	}

	@BeforeEach
	public void setup() {
		// Its own database: clean() below wipes every table, and the shared testdb is what
		// the cached Spring test contexts (migrated once) keep using afterwards
		flyway = Flyway.configure()
				.dataSource(
						"jdbc:h2:mem:moduletest;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
						"sa", "")
				.cleanDisabled(false)
				.load();
	}

	@AfterEach
	public void teardown() {
		flyway.clean();
	}

	@Test
	public void testBuildModuleFlyway() throws Exception {
		String testString = "hello";
		AbstractCodeScanModule module = injectMocks(new MockModule());
		module.buildModule();
		Connection conn = flyway.getConfiguration().getDataSource().getConnection();
		PreparedStatement stmt = conn.prepareStatement("INSERT INTO test (testval) VALUES (?)");
		stmt.setString(1, testString);
		stmt.execute();
		ResultSet rs = conn.createStatement().executeQuery("SELECT testval FROM test");
		rs.next();
		String result = rs.getString("testval");
		Assertions.assertEquals(testString, result);
	}

	@Test
	public void testBuildModuleRegisterWithRuleService() throws Exception {
		AbstractCodeScanModule module = injectMocks(new MockModule());
		module.buildModule();
		BDDMockito.verify(mockRuleEditorService, Mockito.times(1)).registerRuleEditor(moduleName,
				mockRuleManager);
	}

	@Test
	public void testBuildModuleRegisterWithScanningService() throws Exception {
		AbstractCodeScanModule module = injectMocks(new MockModule());
		module.buildModule();
		BDDMockito.verify(mockScanRegistrationService, Mockito.times(1)).registerScanner(moduleName,
				mockScanner);
	}

	@Test
	public void testBuildModuleRegisterWithRuleDesignerService() throws Exception {
		AbstractCodeScanModule module = injectMocks(new MockModule());
		module.buildModule();
		BDDMockito.verify(mockRuleDesignerService, Mockito.times(1)).registerRuleDesigner(
				moduleName,
				mockDesigner);
	}

	@Test
	public void testBuildModuleNameNull() {
		Assertions.assertThrows(IllegalStateException.class,
				() -> {
					AbstractCodeScanModule module = injectMocks(new MockModule(null));
					module.buildModule();
				});
	}

	@Test
	public void testBuildModuleExceptionOccurs() throws Exception {
		Assertions.assertThrows(RuntimeException.class,
				() -> {
					BDDMockito.doThrow(ModuleException.class).when(mockRuleEditorService)
							.registerRuleEditor(moduleName, mockRuleManager);
					AbstractCodeScanModule module = injectMocks(new MockModule());
					module.buildModule();
				});
	}

	@Test
	public void testProvidedRulesAreImportedOnlyForTheModulesOwnContext() throws Exception {
		// The actuator's management port runs in a child context; its refresh event reaches
		// the parent's listeners too, and used to import every provided rule a second time.
		ApplicationContext ownContext = Mockito.mock(ApplicationContext.class);
		ApplicationContext managementContext = Mockito.mock(ApplicationContext.class);
		List<RulesetDto> provided = List.of(new RulesetDto());
		MockModule module = new MockModule();
		module.providedRulesets = provided;
		injectMocks(module);
		ReflectionTestUtils.setField(module, "applicationContext", ownContext);

		module.afterModulesLoaded(new ContextRefreshedEvent(managementContext));
		BDDMockito.verify(mockRulesetService, Mockito.never())
				.registerProvidedRulesets(BDDMockito.any(), BDDMockito.any());

		module.afterModulesLoaded(new ContextRefreshedEvent(ownContext));
		BDDMockito.verify(mockRulesetService).registerProvidedRulesets(moduleName, provided);
	}

	private class MockModule extends AbstractCodeScanModule {
		private String name = moduleName;
		private List<RulesetDto> providedRulesets;

		public MockModule(String name) {
			this.name = name;
		}

		public MockModule() {

		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getSchemaHistoryTable() {
			return schemaLocation;
		}

		@Override
		public String getMigrationsLocation() {
			return migrations;
		}

		@Override
		public ICodeScanner getScanner() {
			return mockScanner;
		}

		@Override
		public IRuleDesigner getRuleDesigner() {
			return mockDesigner;
		}

		@Override
		public IRuleEditor getRuleEditor() {
			return mockRuleManager;
		}

		@Override
		public List<PrivilegeEntity> getModulePrivileges() {
			return null;
		}

		@Override
		public List<RulesetDto> getProvidedRulesets() {
			return providedRulesets;
		}
	}
}
