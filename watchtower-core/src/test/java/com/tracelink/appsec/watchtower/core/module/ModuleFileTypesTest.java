package com.tracelink.appsec.watchtower.core.module;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanConfig;

class ModuleFileTypesTest {
	private ModuleSettingRepository settings;
	private ModuleControlService service;
	private ModuleSettingEntity row;

	@BeforeEach
	void setUp() {
		settings = mock(ModuleSettingRepository.class);
		service = new ModuleControlService(settings);
		row = new ModuleSettingEntity("checkov", true);
		when(settings.findById("checkov")).thenReturn(Optional.of(row));
	}

	@Test
	void policy_fileTypesAreNullUntilAnAdminSetsThem() {
		assertThat(service.policy("checkov").fileTypes()).isNull();
	}

	@Test
	void policy_withoutARowKeepsTheDefaultAndNoFileTypes() {
		assertThat(service.policy("unknown").fileTypes()).isNull();
	}

	@Test
	void changeFileTypes_storesCleanedTypesAndReadsThemBack() {
		service.changeFileTypes("checkov", List.of(" .TF ", ".yaml", ".tf"), 0, "admin");

		assertThat(service.policy("checkov").fileTypes()).containsExactly(".tf", ".yaml");
		assertThat(row.getUpdatedBy()).isEqualTo("admin");
		verify(settings).saveAndFlush(row);
	}

	@Test
	void changeFileTypes_emptyListMeansEveryFile() {
		service.changeFileTypes("checkov", List.of(), 0, "admin");

		assertThat(service.policy("checkov").fileTypes()).isEmpty();
	}

	@Test
	void changeFileTypes_nullResetsToTheScannerDefault() {
		service.changeFileTypes("checkov", List.of(".tf"), 0, "admin");
		service.changeFileTypes("checkov", null, 0, "admin");

		assertThat(service.policy("checkov").fileTypes()).isNull();
	}

	@Test
	void changeFileTypes_rejectsAnInvalidType() {
		assertThatThrownBy(() -> service.changeFileTypes("checkov", List.of("a/b"), 0, "admin"))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void changeFileTypes_rejectsAStaleVersion() {
		assertThatThrownBy(() -> service.changeFileTypes("checkov", List.of(".tf"), 99, "admin"))
				.isInstanceOf(ResponseStatusException.class).hasMessageContaining("changed");
	}

	@Test
	void fingerprint_changesWhenFileTypesChange() {
		when(settings.findAll()).thenReturn(List.of(row));
		String before = service.fingerprint();

		service.changeFileTypes("checkov", List.of(".tf"), 0, "admin");

		assertThat(service.fingerprint()).isNotEqualTo(before);
	}

	@Test
	void fingerprint_isUnchangedForRowsWithoutFileTypes() {
		when(settings.findAll()).thenReturn(List.of(row));

		assertThat(service.fingerprint()).isEqualTo(
				com.tracelink.appsec.watchtower.core.rule.RuleRevision.definition("module-policies", "v1")
						.unordered("policies", List.of("checkov/true/0")).hash());
	}

	@Test
	void changeFileTypes_rejectsAListTooLongForTheColumn() {
		List<String> tooLong = new java.util.ArrayList<>();
		for (int i = 0; i < 30; i++) {
			tooLong.add("." + String.valueOf((char) ('a' + i % 26)).repeat(60) + i);
		}
		assertThatThrownBy(() -> service.changeFileTypes("checkov", tooLong, 0, "admin"))
				.isInstanceOf(IllegalArgumentException.class);
	}

	@Test
	void controlledScanner_usesTheScannersDefaultUntilAnAdminOverridesIt() {
		ModuleControlService controls = mock(ModuleControlService.class);
		ICodeScanner delegate = mock(ICodeScanner.class);
		when(delegate.getDefaultFileTypes()).thenReturn(List.of(".tf", ".yaml"));
		when(controls.policy("checkov"))
				.thenReturn(new ModuleControlService.Policy("checkov", true, 1, null));

		ControlledCodeScanner scanner = new ControlledCodeScanner("checkov", delegate, controls);

		assertThat(scanner.getFileTypes()).containsExactly(".tf", ".yaml");
		assertThat(scanner.getDefaultFileTypes()).containsExactly(".tf", ".yaml");
	}

	@Test
	void controlledScanner_adminOverrideWinsAndEmptyMeansEveryFile() {
		ModuleControlService controls = mock(ModuleControlService.class);
		ICodeScanner delegate = mock(ICodeScanner.class);
		when(delegate.getDefaultFileTypes()).thenReturn(List.of(".tf"));
		when(controls.policy("checkov"))
				.thenReturn(new ModuleControlService.Policy("checkov", true, 2, List.of(".yml")));
		assertThat(new ControlledCodeScanner("checkov", delegate, controls).getFileTypes())
				.containsExactly(".yml");

		when(controls.policy("checkov"))
				.thenReturn(new ModuleControlService.Policy("checkov", true, 3, List.of()));
		assertThat(new ControlledCodeScanner("checkov", delegate, controls).getFileTypes()).isEmpty();
	}

	@Test
	void controlledScanner_identityChangesWhenTheEffectiveFileTypesChange() {
		ModuleControlService controls = mock(ModuleControlService.class);
		ICodeScanner delegate = mock(ICodeScanner.class);
		CodeScanConfig config = new CodeScanConfig();
		when(delegate.getExecutionIdentity(any())).thenReturn(
				new com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity("X", "1", "abc", true));
		when(delegate.executionName()).thenReturn("X");
		when(delegate.getDefaultFileTypes()).thenReturn(List.of(".tf"));
		when(controls.policy("checkov"))
				.thenReturn(new ModuleControlService.Policy("checkov", true, 1, null));
		String withTf = new ControlledCodeScanner("checkov", delegate, controls)
				.getExecutionIdentity(config).fingerprint();

		// A release that changes a scanner's default must not reuse reports built under the old one.
		when(delegate.getDefaultFileTypes()).thenReturn(List.of(".tf", ".yaml"));
		String withTfAndYaml = new ControlledCodeScanner("checkov", delegate, controls)
				.getExecutionIdentity(config).fingerprint();

		assertThat(withTfAndYaml).isNotEqualTo(withTf);
	}
}
