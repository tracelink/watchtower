package com.tracelink.appsec.watchtower.core.rule;

import java.util.Arrays;

import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.BDDMockito;
import org.mockito.Mock;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;

@ExtendWith({SpringExtension.class, MockitoExtension.class})
@MockitoSettings(strictness = Strictness.LENIENT)
public class RuleDesignerServiceTest {

	@Mock
	private IRuleDesigner mockRuleDesigner;

	@Test
	public void testFileTypesAreEmptyWithoutAnAdminLimit() {
		RuleDesignerService rds = new RuleDesignerService();
		Assertions.assertTrue(rds.getFileTypes("regex").isEmpty(), "no module controls: no limit");

		com.tracelink.appsec.watchtower.core.module.ModuleControlService controls =
				BDDMockito.mock(com.tracelink.appsec.watchtower.core.module.ModuleControlService.class);
		BDDMockito.when(controls.policy("regex")).thenReturn(
				new com.tracelink.appsec.watchtower.core.module.ModuleControlService.Policy("regex", true, 1, null));
		org.springframework.test.util.ReflectionTestUtils.setField(rds, "moduleControls", controls);
		Assertions.assertTrue(rds.getFileTypes("regex").isEmpty(), "the scanner's default is not an admin limit");
	}

	@Test
	public void testFileTypesAreTheLimitAnAdminSet() {
		RuleDesignerService rds = new RuleDesignerService();
		com.tracelink.appsec.watchtower.core.module.ModuleControlService controls =
				BDDMockito.mock(com.tracelink.appsec.watchtower.core.module.ModuleControlService.class);
		BDDMockito.when(controls.policy("regex")).thenReturn(new com.tracelink.appsec.watchtower.core.module.ModuleControlService.Policy(
				"regex", true, 2, java.util.List.of(".java", ".xml")));
		org.springframework.test.util.ReflectionTestUtils.setField(rds, "moduleControls", controls);

		MatcherAssert.assertThat(rds.getFileTypes("regex"), Matchers.contains(".java", ".xml"));
	}

	@Test
	public void testRegisterDesignerNullName() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					RuleDesignerService rds = new RuleDesignerService();
					rds.registerRuleDesigner(null, mockRuleDesigner);
				});
	}

	@Test
	public void testRegisterDesignerNullDesigner() throws Exception {
		Assertions.assertThrows(IllegalArgumentException.class,
				() -> {
					RuleDesignerService rds = new RuleDesignerService();
					rds.registerRuleDesigner("Mock", null);
				});
	}

	@Test
	public void testRegisterDesignerSameName() throws Exception {
		Assertions.assertThrows(ModuleException.class,
				() -> {
					RuleDesignerService rds = new RuleDesignerService();
					rds.registerRuleDesigner("Mock", mockRuleDesigner);
					rds.registerRuleDesigner("Mock", mockRuleDesigner);
				});
	}

	@Test
	public void testGetKnownModules() throws Exception {
		RuleDesignerService rds = new RuleDesignerService();
		rds.registerRuleDesigner("Mock", mockRuleDesigner);
		Authentication auth = new AnonymousAuthenticationToken("foo", "bar",
				Arrays.asList(new SimpleGrantedAuthority("authority")));
		BDDMockito.when(mockRuleDesigner.hasAuthority(BDDMockito.anyString())).thenReturn(true);
		MatcherAssert.assertThat(rds.getKnownModulesForUser(auth), Matchers.contains("Mock"));
	}

	@Test
	public void getDefaultDesignerModuleName() throws Exception {
		RuleDesignerService rds = new RuleDesignerService();
		Assertions.assertEquals(null, rds.getDefaultDesignerModule());
		rds.registerRuleDesigner("Zz", mockRuleDesigner);
		rds.registerRuleDesigner("Aa", mockRuleDesigner);
		Assertions.assertEquals("Aa", rds.getDefaultDesignerModule());
	}

	@Test
	public void testGetDefaultDesignerView() throws Exception {
		RuleDesignerModelAndView mockMAV = BDDMockito.mock(RuleDesignerModelAndView.class);
		BDDMockito.when(mockRuleDesigner.getDefaultRuleDesignerModelAndView()).thenReturn(mockMAV);

		RuleDesignerService rds = new RuleDesignerService();
		rds.registerRuleDesigner("Mock", mockRuleDesigner);

		Assertions.assertEquals(mockMAV,
				rds.getDefaultDesignerModelAndView("Mock"));
	}

	@Test
	public void testGetDefaultDesignerViewException() throws Exception {
		RuleDesignerService rds = new RuleDesignerService();
		try {
			rds.getDefaultDesignerModelAndView("Mock");
			Assertions.fail("Should have thrown an exception");
		} catch (ModuleNotFoundException e) {
			Assertions.assertTrue(e.getMessage().contains("No designer exists"));
		}
	}

}
