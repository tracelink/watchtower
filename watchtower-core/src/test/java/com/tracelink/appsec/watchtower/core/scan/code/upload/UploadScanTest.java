package com.tracelink.appsec.watchtower.core.scan.code.upload;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.upload.UploadScan;


public class UploadScanTest {

	@Test
	public void testDAO() {
		String name = "name";
		String ruleSet = "ruleSet";
		Path filePath = Paths.get("some", "path");
		String user = "user";
		long submitDate = System.currentTimeMillis();

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setRuleSetName(ruleSet);
		scan.setFilePath(filePath);
		scan.setUser(user);
		scan.setSubmitDate(submitDate);

		Assertions.assertEquals(name, scan.getName());
		Assertions.assertEquals(ruleSet, scan.getRuleSetName());
		Assertions.assertEquals(filePath, scan.getFilePath());
		Assertions.assertEquals(user, scan.getUser());
		Assertions.assertEquals(submitDate, scan.getSubmitDate());
	}
}
