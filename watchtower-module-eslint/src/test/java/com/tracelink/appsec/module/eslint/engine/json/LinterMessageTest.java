package com.tracelink.appsec.module.eslint.engine.json;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.module.eslint.engine.LinterMessage;

public class LinterMessageTest {

	@Test
	public void testGettersAndSetters() {
		LinterMessage message = new LinterMessage();
		message.setRuleId("no-xyz");
		message.setMessage("Do not do this");
		message.setMessageId("bad");
		message.setNodeType("ObjectExpression");
		message.setSeverity(1);
		message.setFatal(false);
		message.setLine(1);
		message.setColumn(2);
		message.setEndLine(3);
		message.setEndColumn(4);

		Assertions.assertEquals("no-xyz", message.getRuleId());
		Assertions.assertEquals("Do not do this", message.getMessage());
		Assertions.assertEquals("bad", message.getMessageId());
		Assertions.assertEquals("ObjectExpression", message.getNodeType());
		Assertions.assertEquals(1, message.getSeverity());
		Assertions.assertFalse(message.isFatal());
		Assertions.assertEquals(1, message.getLine());
		Assertions.assertEquals(2, message.getColumn());
		Assertions.assertEquals(3, message.getEndLine());
		Assertions.assertEquals(4, message.getEndColumn());
	}
}
