package com.tracelink.appsec.watchtower.core.module;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.mvc.support.RedirectAttributesModelMap;

import com.tracelink.appsec.watchtower.core.mvc.WatchtowerModelAndView;
import com.tracelink.appsec.watchtower.core.rule.RuleEditorService;
import com.tracelink.appsec.watchtower.core.rule.RuleService;
import com.tracelink.appsec.watchtower.core.scan.ScanRegistrationService;

class ModuleControlFileTypesControllerTest {
	private ModuleControlService controls;
	private ModuleControlController controller;
	private Authentication auth;
	private RedirectAttributes redirect;

	@BeforeEach
	void setUp() {
		controls = mock(ModuleControlService.class);
		ScanRegistrationService registry = mock(ScanRegistrationService.class);
		when(registry.getScannerNames()).thenReturn(List.of("Checkov", "PMD"));
		controller = new ModuleControlController(controls, registry, mock(RuleService.class),
				mock(RuleEditorService.class));
		auth = mock(Authentication.class);
		when(auth.getName()).thenReturn("admin");
		redirect = new RedirectAttributesModelMap();
	}

	@Test
	void savesTheTypedTypesSplitOnCommasSpacesAndLines() {
		String view = controller.changeFileTypes("Checkov", 3, ".tf, .yaml\n dockerfile", false, auth, redirect);

		verify(controls).changeFileTypes("Checkov", List.of(".tf", ".yaml", "dockerfile"), 3, "admin");
		assertThat(view).isEqualTo("redirect:/configuration/modules");
		assertThat(redirect.getFlashAttributes()).containsKey(WatchtowerModelAndView.SUCCESS_NOTIFICATION);
	}

	@Test
	void blankInputMeansEveryFile() {
		controller.changeFileTypes("Checkov", 3, "  ", false, auth, redirect);

		verify(controls).changeFileTypes("Checkov", List.of(), 3, "admin");
	}

	@Test
	void useDefaultReturnsToTheScannersOwnTypes() {
		controller.changeFileTypes("Checkov", 3, ".ignored", true, auth, redirect);

		verify(controls).changeFileTypes("Checkov", null, 3, "admin");
	}

	@Test
	void anInvalidTypeIsShownToTheAdminInsteadOfFailingThePage() {
		doThrow(new IllegalArgumentException("Not a file type: a/b. Use an extension such as .tf"))
				.when(controls).changeFileTypes(eq("Checkov"), any(), anyLong(), any());

		String view = controller.changeFileTypes("Checkov", 3, "a/b", false, auth, redirect);

		assertThat(view).isEqualTo("redirect:/configuration/modules");
		assertThat(redirect.getFlashAttributes().get(WatchtowerModelAndView.FAILURE_NOTIFICATION))
				.asString().contains("Not a file type");
	}

	@Test
	void anUnknownModuleIsShownAsAFailureNotAServerError() {
		String view = controller.changeFileTypes("Nope", 0, ".tf", false, auth, redirect);

		assertThat(view).isEqualTo("redirect:/configuration/modules");
		assertThat(redirect.getFlashAttributes().get(WatchtowerModelAndView.FAILURE_NOTIFICATION))
				.asString().contains("Unknown module");
		org.mockito.Mockito.verifyNoInteractions(controls);
	}

	@Test
	void anUnknownModuleCannotBeTurnedOffOrOnEither() {
		String view = controller.change("Nope", false, 0, auth, redirect);

		assertThat(view).isEqualTo("redirect:/configuration/modules");
		assertThat(redirect.getFlashAttributes().get(WatchtowerModelAndView.FAILURE_NOTIFICATION))
				.asString().contains("Unknown module");
		org.mockito.Mockito.verifyNoInteractions(controls);
	}
}
