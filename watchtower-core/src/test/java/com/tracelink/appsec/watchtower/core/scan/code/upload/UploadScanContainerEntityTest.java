package com.tracelink.appsec.watchtower.core.scan.code.upload;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.code.upload.entity.UploadScanContainerEntity;


public class UploadScanContainerEntityTest {

	@Test
	public void testDAO() {
		String name = "name";
		String submitter = "submitter";
		String ticket = "ticket";
		String ruleSet = "ruleSet";
		String s3Key = "uploads/some-key.zip";

		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setName(name);
		container.setSubmitter(submitter);
		container.setTicket(ticket);
		container.setRuleSet(ruleSet);
		container.setStorageKey(s3Key);

		Assertions.assertEquals(name, container.getName());
		Assertions.assertEquals(submitter, container.getSubmitter());
		Assertions.assertEquals(ticket, container.getTicket());
		Assertions.assertEquals(ruleSet, container.getRuleSet());
		Assertions.assertEquals(s3Key, container.getStorageKey());
	}
}
