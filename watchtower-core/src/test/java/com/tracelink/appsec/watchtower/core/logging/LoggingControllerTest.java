package com.tracelink.appsec.watchtower.core.logging;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.BDDMockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.tracelink.appsec.watchtower.core.WatchtowerTestApplication;
import com.tracelink.appsec.watchtower.core.auth.model.CorePrivilege;
import com.tracelink.appsec.watchtower.core.ui.HtmlAssertions;

import ch.qos.logback.classic.Level;

@ExtendWith(SpringExtension.class)
@SpringBootTest(classes = WatchtowerTestApplication.class)
@AutoConfigureMockMvc
public class LoggingControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@MockitoBean
	LogsService mockLogsService;

	///////////////////
	// Get logging
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.LOGGING_VIEW_NAME})
	public void testGetLogging() throws Exception {
		Level level = Level.INFO;
		String levelStr = level.levelStr;
		List<String> logs = new ArrayList<String>();
		logs.add("2026-10-16 13:13:34.120 c.t.a.w.c.s.a.IntegrationHealthService WARN  - Check failed");
		logs.add("plain line");

		BDDMockito.when(mockLogsService.getLogsLevel()).thenReturn(level);
		BDDMockito.when(mockLogsService.getLogs(200)).thenReturn(logs);

		MvcResult result = mockMvc.perform(MockMvcRequestBuilders.get("/logging"))
				.andExpect(MockMvcResultMatchers.model().attribute("currentLogLevel",
						Matchers.is(levelStr)))
				.andExpect(MockMvcResultMatchers.model().attribute("logOptions",
						Matchers.hasItems(Level.TRACE, Level.DEBUG, Level.INFO, Level.WARN,
								Level.ERROR)))
				.andExpect(MockMvcResultMatchers.model().attribute("logs", Matchers.is(List.of(
						new LogLine("13:13:34", "2026-10-16", "WARN",
								"c.t.a.w.c.s.a.IntegrationHealthService", "Check failed"),
						new LogLine("", "", "", "", "plain line")))))
				.andExpect(MockMvcResultMatchers.model().attribute("lineLimit", Matchers.is(200)))
				.andReturn();
		HtmlAssertions.assertHtmlIntegrity(result);
		String html = result.getResponse().getContentAsString();
		// Level chip, tinted warning line, short logger with the full name on hover.
		Assertions.assertTrue(html.contains("data-level=\"warn\""));
		Assertions.assertTrue(html.contains(">IntegrationHealthService<"));
		Assertions.assertTrue(html.contains("data-tip=\"c.t.a.w.c.s.a.IntegrationHealthService\""));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.LOGGING_VIEW_NAME})
	public void testGetLoggingAcceptsOnlySupportedLineLimits() throws Exception {
		BDDMockito.when(mockLogsService.getLogsLevel()).thenReturn(Level.INFO);
		BDDMockito.when(mockLogsService.getLogs(1000)).thenReturn(List.of());

		mockMvc.perform(MockMvcRequestBuilders.get("/logging").param("lines", "1000"))
				.andExpect(MockMvcResultMatchers.model().attribute("lineLimit", Matchers.is(1000)));
		BDDMockito.verify(mockLogsService).getLogs(1000);

		mockMvc.perform(MockMvcRequestBuilders.get("/logging").param("lines", "999999"))
				.andExpect(MockMvcResultMatchers.model().attribute("lineLimit", Matchers.is(200)));
	}

	///////////////////
	// Set logging
	///////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.LOGGING_MODIFY_NAME})
	public void testSetLoggingInvalid() throws Exception {
		Level level = Level.ALL;
		String levelStr = level.levelStr;
		ArgumentCaptor<Level> levelCaptor = ArgumentCaptor.forClass(Level.class);

		mockMvc.perform(MockMvcRequestBuilders.post("/logging/set").param("loglevel", levelStr)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection());

		BDDMockito.verify(mockLogsService).setLogsLevel(levelCaptor.capture());
		Level capturedLevel = levelCaptor.getValue();
		Assertions.assertEquals(Level.INFO, capturedLevel);
	}

	@Test
	@WithMockUser(username = "levelchanger", authorities = {CorePrivilege.LOGGING_MODIFY_NAME})
	public void testSetLoggingRecordsWhoChangedIt() throws Exception {
		ch.qos.logback.classic.Logger controllerLogger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
				.getLogger(LoggingController.class);
		ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
				new ch.qos.logback.core.read.ListAppender<>();
		appender.start();
		controllerLogger.addAppender(appender);
		try {
			mockMvc.perform(MockMvcRequestBuilders.post("/logging/set")
					.param("loglevel", Level.DEBUG.levelStr)
					.with(SecurityMockMvcRequestPostProcessors.csrf()))
					.andExpect(MockMvcResultMatchers.status().is3xxRedirection());

			Assertions.assertTrue(appender.list.stream()
					.map(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage)
					.anyMatch(message -> message.contains("levelchanger")
							&& message.contains("DEBUG")),
					"the log must say who changed the level and to what");
		} finally {
			controllerLogger.detachAppender(appender);
		}
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.LOGGING_MODIFY_NAME})
	public void testSetLoggingValid() throws Exception {
		Level level = Level.WARN;
		String levelStr = level.levelStr;
		ArgumentCaptor<Level> levelCaptor = ArgumentCaptor.forClass(Level.class);

		mockMvc.perform(MockMvcRequestBuilders.post("/logging/set").param("loglevel", levelStr)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection());

		BDDMockito.verify(mockLogsService).setLogsLevel(levelCaptor.capture());
		Level capturedLevel = levelCaptor.getValue();
		Assertions.assertEquals(Level.WARN, capturedLevel);
	}

	//////////////////
	// Do Download
	//////////////////
	@Test
	@WithMockUser(authorities = {CorePrivilege.LOGGING_DOWNLOAD_NAME})
	public void testDownload() throws Exception {
		byte[] expectedContent = new byte[512];
		new SecureRandom().nextBytes(expectedContent);

		Path temp = Files.createTempFile(null, ".zip");
		Files.write(temp, expectedContent);

		BDDMockito.when(mockLogsService.generateLogsZip()).thenReturn(temp);

		mockMvc.perform(MockMvcRequestBuilders.get("/logging/download"))
				.andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
				.andExpect(MockMvcResultMatchers.content().bytes(expectedContent));
	}

	@Test
	@WithMockUser(authorities = {CorePrivilege.LOGGING_DOWNLOAD_NAME})
	public void testDownloadError() throws Exception {
		BDDMockito.given(mockLogsService.generateLogsZip()).willThrow(IOException.class);

		mockMvc.perform(MockMvcRequestBuilders.get("/logging/download"))
				.andExpect(MockMvcResultMatchers.status().is4xxClientError());
	}

}
