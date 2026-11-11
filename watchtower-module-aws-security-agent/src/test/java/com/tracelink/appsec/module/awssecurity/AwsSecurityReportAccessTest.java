package com.tracelink.appsec.module.awssecurity;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.mock.web.*;
import com.tracelink.appsec.watchtower.core.scan.apiintegration.ApiIntegrationService;
import com.tracelink.appsec.watchtower.core.scan.code.report.ScanReportReader;

/** Method security with a small context: no application startup, database or migrations. */
class AwsSecurityReportAccessTest {
    @Configuration @EnableMethodSecurity
    static class Config {
        @Bean AwsSecurityEvidencePolicy evidencePolicy(){return new AwsSecurityEvidencePolicy("","");}
        @Bean AwsSecurityRunRepository runs() { return mock(AwsSecurityRunRepository.class); }
        @Bean AwsSecurityImporter importer() { return mock(AwsSecurityImporter.class); }
        @Bean AwsSecurityAssessmentService assessments() { return mock(AwsSecurityAssessmentService.class); }
        @Bean ApiIntegrationService integrations() { return mock(ApiIntegrationService.class); }
        @Bean com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook.BBWebhookManagementService webhooks() { return mock(com.tracelink.appsec.watchtower.core.scan.apiintegration.webhook.BBWebhookManagementService.class); }
        @Bean ScanReportReader localReports() { return mock(ScanReportReader.class); }
        @Bean AwsSecurityReportController controller(AwsSecurityRunRepository r, AwsSecurityImporter i, AwsSecurityAssessmentService a) { return new AwsSecurityReportController(r, i, a); }
    }
    @Test void detailSourceStatusAndEveryExportRequireScanViewAuthority() throws Exception {
        try (var context = new AnnotationConfigApplicationContext(Config.class)) {
            var controller = context.getBean(AwsSecurityReportController.class); var request = new MockHttpServletRequest("GET", "/scan/report/1/aws/export");
            // Injecting the mock called its autowired setter; only the controller's own calls count below.
            clearInvocations(context.getBean(ApiIntegrationService.class));
            SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "unused", "Repository Settings View"));
            assertThrows(AccessDeniedException.class, () -> controller.status(1, request));
            assertThrows(AccessDeniedException.class, () -> controller.detail(1, "a".repeat(64), 0, request, new MockHttpServletResponse()));
            assertThrows(AccessDeniedException.class, () -> controller.titles(1, 0, request, new MockHttpServletResponse()));
            assertThrows(AccessDeniedException.class, () -> controller.source(1, "a".repeat(64), 0, 0, request, new MockHttpServletResponse()));
            for (String format : java.util.List.of("json", "sarif", "csv", "html")) assertThrows(AccessDeniedException.class, () -> controller.export(1, format, request, new MockHttpServletResponse()));
            verifyNoInteractions(context.getBean(AwsSecurityRunRepository.class), context.getBean(ApiIntegrationService.class));
            SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("viewer", "unused", "Scan Results View"));
            assertDoesNotThrow(() -> controller.status(1, request));
        } finally { SecurityContextHolder.clearContext(); }
    }
}
