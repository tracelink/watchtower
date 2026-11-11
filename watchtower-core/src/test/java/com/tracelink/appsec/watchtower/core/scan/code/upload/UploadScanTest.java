package com.tracelink.appsec.watchtower.core.scan.code.upload;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;


public class UploadScanTest {

	@Test
	public void testDAO() {
		String name = "name";
		String ruleSet = "ruleSet";
		String s3Key = "uploads/some-key.zip";
		String user = "user";

		UploadScan scan = new UploadScan();
		scan.setName(name);
		scan.setRuleSetName(ruleSet);
		scan.setStorageKey(s3Key);
		scan.setUser(user);

		Assertions.assertEquals(name, scan.getName());
		Assertions.assertEquals(ruleSet, scan.getRuleSetName());
		Assertions.assertEquals(s3Key, scan.getStorageKey());
		Assertions.assertEquals(user, scan.getUser());
	}
}
