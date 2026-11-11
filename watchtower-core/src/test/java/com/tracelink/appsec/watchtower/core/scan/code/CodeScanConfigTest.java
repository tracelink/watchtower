package com.tracelink.appsec.watchtower.core.scan.code;

import java.util.Collections;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * IMPROVEMENT_PLAN.md item 2.7. {@code PRScanAgent} populating {@code changedFilePaths} from
 * {@code changedFileDiffs.keySet()} is covered where that field is introduced (item 2.5).
 */
public class CodeScanConfigTest {

	@Test
	public void testChangedFilePathsDefaultsEmpty() {
		Assertions.assertTrue(new CodeScanConfig().getChangedFilePaths().isEmpty());
	}

	@Test
	public void testChangedFilePathsRoundTrips() {
		CodeScanConfig config = new CodeScanConfig();
		Set<String> paths = Collections.singleton("src/main/Foo.java");
		config.setChangedFilePaths(paths);
		Assertions.assertEquals(paths, config.getChangedFilePaths());
	}

	@Test
	public void testChangedFilePathsSetNullFallsBackToEmpty() {
		CodeScanConfig config = new CodeScanConfig();
		config.setChangedFilePaths(null);
		Assertions.assertTrue(config.getChangedFilePaths().isEmpty());
	}
}
