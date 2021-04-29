package com.tracelink.appsec.watchtower.core.scan.upload;

import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.scan.upload.entity.UploadScanContainerEntity;


public class UploadScanContainerEntityTest {

	@Test
	public void testDAO() {
		String name = "name";
		String submitter = "submitter";
		String ticket = "ticket";
		String ruleSet = "ruleSet";
		Path filePath = Paths.get("path");

		UploadScanContainerEntity container = new UploadScanContainerEntity();
		container.setName(name);
		container.setSubmitter(submitter);
		container.setTicket(ticket);
		container.setRuleSet(ruleSet);
		container.setZipPath(filePath);

		Assertions.assertEquals(name, container.getName());
		Assertions.assertEquals(submitter, container.getSubmitter());
		Assertions.assertEquals(ticket, container.getTicket());
		Assertions.assertEquals(ruleSet, container.getRuleSet());
		Assertions.assertEquals(filePath.toAbsolutePath(), container.getZipPath());
	}
}
