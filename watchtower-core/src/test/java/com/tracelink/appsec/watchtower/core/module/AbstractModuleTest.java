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
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.tracelink.appsec.watchtower.core.auth.model.PrivilegeEntity;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.ruleeditor.IRuleEditor;
import com.tracelink.appsec.watchtower.core.module.scanner.IScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;
import com.tracelink.appsec.watchtower.core.rule.RuleEditorService;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;

@ExtendWith(SpringExtension.class)
public class AbstractModuleTest {
	private Flyway flyway;

	@MockBean
	private RulesetService mockRulesetService;

	@MockBean
	private RuleEditorService mockRuleEditorService;

	@MockBean
	private RuleDesignerService mockRuleDesignerService;

	@MockBean
	private ScanRegistrationService mockScanRegistrationService;

	@Mock
	private IScanner mockScanner;

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
	private AbstractModule injectMocks(AbstractModule module) {
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
		flyway = Flyway.configure()
				.dataSource(
						"jdbc:h2:mem:testdb;MODE=MySQL;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE",
						"sa", "")
				.load();
	}

	@AfterEach
	public void teardown() {
		flyway.clean();
	}

	@Test
	public void testBuildModuleFlyway() throws Exception {
		String testString = "hello";
		AbstractModule module = injectMocks(new MockModule());
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
		AbstractModule module = injectMocks(new MockModule());
		module.buildModule();
		BDDMockito.verify(mockRuleEditorService, Mockito.times(1)).registerRuleEditor(moduleName,
				mockRuleManager);
	}

	@Test
	public void testBuildModuleRegisterWithScanninService() throws Exception {
		AbstractModule module = injectMocks(new MockModule());
		module.buildModule();
		BDDMockito.verify(mockScanRegistrationService, Mockito.times(1)).registerScanner(moduleName,
				mockScanner);
	}

	@Test
	public void testBuildModuleRegisterWithRuleDesignerService() throws Exception {
		AbstractModule module = injectMocks(new MockModule());
		module.buildModule();
		BDDMockito.verify(mockRuleDesignerService, Mockito.times(1)).registerRuleDesigner(
				moduleName,
				mockDesigner);
	}

	@Test
	public void testBuildModuleNameNull() {
		Assertions.assertThrows(IllegalStateException.class,
				() -> {
					AbstractModule module = injectMocks(new MockModule(null));
					module.buildModule();
				});
	}

	@Test
	public void testBuildModuleExceptionOccurs() throws Exception {
		Assertions.assertThrows(RuntimeException.class,
				() -> {
					BDDMockito.doThrow(ModuleException.class).when(mockRuleEditorService)
							.registerRuleEditor(moduleName, mockRuleManager);
					AbstractModule module = injectMocks(new MockModule());
					module.buildModule();
				});
	}

	private class MockModule extends AbstractModule {
		private String name = moduleName;

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
		public IScanner getScanner() {
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
			return null;
		}
	}
}
