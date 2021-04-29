package com.tracelink.appsec.module.pmd.scanner;

import java.io.IOException;
import java.io.Writer;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class NoopWriterTest {

	@Test
	public void testWriterDoesNoOps() {
		try {
			Writer writer = new NoopWriter();
			writer.write("operation");
			writer.flush();
			writer.close();
			// all of these would fail normally
			writer.write("wouldn't work normally");
			writer.flush();
			writer.close();
		} catch (IOException e) {
			Assertions.fail("an operation occurred");
		}
	}

}
