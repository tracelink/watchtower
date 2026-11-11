package com.tracelink.appsec.watchtower.core.ui;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;

/**
 * Guards upload and image report parity: both use the shared finding workspace rather than
 * rebuilding a scan-specific report table.
 */
class ReportSeverityColumnOrderTest {

	@Test
	void uploadScanReportUsesSharedFindingWorkspace() throws IOException {
		assertUsesFindingWorkspace("watchtower-core/src/main/resources/templates/upload_scan/scanreport.html");
	}

	@Test
	void imageScanReportUsesSharedFindingWorkspace() throws IOException {
		assertUsesFindingWorkspace("watchtower-core/src/main/resources/templates/image_scan/scanreport.html");
	}

	private void assertUsesFindingWorkspace(String relativeTemplatePath) throws IOException {
		Path repoRoot = TemplateModuleScanner.repoRoot();
		String html = Files.readString(repoRoot.resolve(relativeTemplatePath));
		assertTrue(html.contains("fragments/findings :: workspace"),
				relativeTemplatePath + ": expected the shared finding workspace fragment");
		assertTrue(!html.contains("table datatable") && !html.contains("<table"),
				relativeTemplatePath + ": report-only DataTable should have been removed");
	}
}
