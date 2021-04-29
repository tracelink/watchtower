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
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.tracelink.appsec.watchtower.core.module.ModuleException;
import com.tracelink.appsec.watchtower.core.module.ModuleNotFoundException;
import com.tracelink.appsec.watchtower.core.module.designer.IRuleDesigner;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDesignerModelAndView;

@ExtendWith(SpringExtension.class)
public class RuleDesignerServiceTest {

	@Mock
	private IRuleDesigner mockRuleDesigner;

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
		BDDMockito.when(mockRuleDesigner.getRuleDesignerModelAndView()).thenReturn(mockMAV);

		RuleDesignerService rds = new RuleDesignerService();
		rds.registerRuleDesigner("Mock", mockRuleDesigner);

		Assertions.assertEquals(mockMAV,
				rds.getDesignerModelAndView("Mock"));
	}

	@Test
	public void testGetDefaultDesignerViewException() throws Exception {
		RuleDesignerService rds = new RuleDesignerService();
		try {
			rds.getDesignerModelAndView("Mock");
			Assertions.fail("Should have thrown an exception");
		} catch (ModuleNotFoundException e) {
			Assertions.assertTrue(e.getMessage().contains("No designer exists"));
		}
	}

}
