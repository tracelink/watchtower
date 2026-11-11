package com.tracelink.appsec.module.opengrep;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.opengrep.scanner.OpengrepScanner;

class OpengrepFileTypesTest {
	@Test
	void defaultTypesCoverEveryLanguageTheAdapterAdmits() {
		assertThat(new OpengrepScanner().getDefaultFileTypes()).contains(".py", ".js", ".ts", ".java",
				".yaml", ".yml");
	}
}
