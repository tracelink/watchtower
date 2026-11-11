package com.tracelink.appsec.watchtower.core.scan.code.scm.bb;

import static org.junit.jupiter.api.Assertions.*;
import static com.github.tomakehurst.wiremock.client.WireMock.*;

import java.util.List;
import java.util.ArrayList;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.Mockito;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.tracelink.appsec.watchtower.core.WireMockExtension;
import com.tracelink.appsec.watchtower.core.scan.code.scm.api.bb.*;

class BBCloudWebhookTest {
    @RegisterExtension
    public WireMockExtension server = new WireMockExtension(WireMockConfiguration.wireMockConfig().dynamicPort());
    private BBCloudIntegrationEntity entity;
    private BBCloudApi api;
    private static final String HOOKS = "/workspaces/team/hooks";
    private static final String CALLBACK = "https://wt.example/rest/scan/bb";

    @BeforeEach void setup() {
        server.resetMappings();
        entity = Mockito.spy(new BBCloudIntegrationEntity());
        Mockito.doReturn(server.baseUrl()).when(entity).getApiBase();
        entity.setApiLabel("bb"); entity.setWorkspace("team");
        entity.setUser("user"); entity.setAuth("token");
        api = new BBCloudApi(entity);
    }

    private String hook(String uuid, String url) {
        return "{\"uuid\":\"" + uuid + "\",\"url\":\"" + url
                + "\",\"active\":true,\"secret_set\":true,\"secret\":\"DO-NOT-RETURN\",\"events\":[\"pullrequest:created\"]}";
    }
    private void list(String path, String body) { stubFor(get(urlEqualTo(path)).willReturn(okJson(body))); }

    @Test void paginatesAndUsesExactOwnershipWithSafeDisplayUrls() {
        list(HOOKS, "{\"values\":[" + hook("owned", CALLBACK) + "],\"next\":\"" + server.baseUrl() + HOOKS + "?page=2\"}");
        list(HOOKS + "?page=2", "{\"values\":[" + hook("foreign", "https://user:password@other.example/hook?token=secret#private")
                + "," + hook("query", CALLBACK + "?token=secret") + "]}");
        var hooks = api.listWorkspaceHooks("https://wt.example/");
        assertEquals(3, hooks.size());
        assertTrue(hooks.get(0).owned()); assertTrue(hooks.get(0).active());
        assertTrue(hooks.get(0).secretSet());
        assertEquals(List.of("pullrequest:created"), hooks.get(0).events());
        assertFalse(hooks.get(1).owned()); assertFalse(hooks.get(2).owned());
        assertEquals("other.example/hook", hooks.get(1).urlHostPath());
        assertFalse(hooks.toString().contains("password"));
        assertFalse(hooks.toString().contains("token="));
        assertFalse(hooks.toString().contains("DO-NOT-RETURN"));
    }

    @Test void failedListingNeverCreatesAHookOrLeaksTheProviderBody() {
        for (int status : List.of(401, 403, 404, 500)) {
            stubFor(get(urlEqualTo(HOOKS)).willReturn(aResponse().withStatus(status).withBody("PRIVATE-TOKEN")));
            var ex = assertThrows(BBWebhookException.class, () -> api.register(null, "https://wt.example"));
            assertEquals(status, ex.getStatus()); assertFalse(ex.getMessage().contains("PRIVATE-TOKEN"));
        }
        verify(0, postRequestedFor(anyUrl()));
    }

    @Test void rateLimitIsExposedInSecondsWithoutBlockingTheCaller() {
        stubFor(get(urlEqualTo(HOOKS)).willReturn(aResponse().withStatus(429).withHeader("Retry-After", "37")));
        var ex = assertThrows(BBWebhookException.class, () -> api.listWorkspaceHooks("https://wt.example"));
        assertEquals("RATE_LIMITED", ex.getCode()); assertEquals(37, ex.getRetryAfterSeconds());
        verify(1, getRequestedFor(urlEqualTo(HOOKS)));
    }

    @Test void rejectsUntrustedNextUrlsAndPaginationLoops() {
        for (String next : List.of("https://attacker.example/hooks", server.baseUrl() + "/different", server.baseUrl() + HOOKS)) {
            list(HOOKS, "{\"values\":[],\"next\":\"" + next + "\"}");
            assertThrows(IllegalStateException.class, () -> api.listWorkspaceHooks("https://wt.example"));
        }
        verify(0, getRequestedFor(urlEqualTo("/different")));
    }

    @Test void repoListingAndSlugValidation() {
        String path = "/repositories/team/repo-one/hooks";
        list(path, "{\"values\":[" + hook("repo", CALLBACK) + "]}");
        assertEquals("repo", api.listRepoHooks("repo-one", "https://wt.example").getFirst().uuid());
        for (String slug : List.of("../team", "repo?next=x", "repo/hooks", "")) {
            assertThrows(IllegalArgumentException.class, () -> entity.makeRepoHooksUrl(slug));
        }
    }

    @Test void registrationAndUnregistrationPreserveExistingSigningSecret() {
        entity.setWebhookSecret("existing-secret");
        list(HOOKS, "{\"values\":[" + hook("known", CALLBACK) + "]}");
        stubFor(put(urlEqualTo(HOOKS + "/known")).willReturn(okJson("{\"uuid\":\"known\"}")));
        stubFor(delete(urlEqualTo(HOOKS + "/known")).willReturn(noContent()));
        api.register(null, "https://wt.example");
        verify(putRequestedFor(urlEqualTo(HOOKS + "/known")).withRequestBody(matchingJsonPath("$.secret", equalTo("existing-secret"))));
        api.unregister();
        assertNull(entity.getWebhookUuid()); assertEquals("existing-secret", entity.getWebhookSecret());
        api.register(null, "https://wt.example");
        assertEquals("existing-secret", entity.getWebhookSecret());
    }

    @Test void newSecretSurvivesAmbiguousCreationFailureForRetry() {
        list(HOOKS, "{\"values\":[]}");
        stubFor(post(urlEqualTo(HOOKS)).willReturn(serverError().withBody("PRIVATE-TOKEN")));
        var ex = assertThrows(IllegalStateException.class, () -> api.register(null, "https://wt.example"));
        assertNotNull(entity.getWebhookSecret());
        assertFalse(ex.getMessage().contains("PRIVATE-TOKEN"));
        String secret = entity.getWebhookSecret();
        assertThrows(IllegalStateException.class, () -> api.register(null, "https://wt.example"));
        assertEquals(secret, entity.getWebhookSecret());
    }
    @Test void createsRepoHookWithReusedSecretAndSupportedEvents() {
        entity.setWebhookSecret("stable-secret");String path="/repositories/team/repo/hooks";
        list(path,"{\"values\":[]}");stubFor(post(urlEqualTo(path)).willReturn(created().withBody("{\"uuid\":\"new-id\"}")));
        var result=api.upsertHook("repo","https://wt.example",List.of("pullrequest:created","pullrequest:updated"),true,null,false);
        assertEquals("CREATED",result.outcome());assertEquals("new-id",result.uuid());
        verify(postRequestedFor(urlEqualTo(path)).withRequestBody(matchingJsonPath("$.secret",equalTo("stable-secret"))).withRequestBody(matchingJsonPath("$.url",equalTo(CALLBACK))));
    }
    @Test void unchangedHookDoesNotSpendAnUpdateAndRotationForcesIt() {
        entity.setWebhookSecret("stable-secret");String path="/repositories/team/repo/hooks";
        list(path,"{\"values\":["+hook("known",CALLBACK)+"]}");stubFor(put(urlEqualTo(path+"/known")).willReturn(okJson("{\"uuid\":\"known\"}")));
        assertEquals("UNCHANGED",api.upsertHook("repo","https://wt.example",List.of("pullrequest:created"),true,null,false).outcome());
        verify(0,putRequestedFor(anyUrl()));
        assertEquals("UPDATED",api.upsertHook("repo","https://wt.example",List.of("pullrequest:created"),true,"known",true).outcome());
        verify(putRequestedFor(urlEqualTo(path+"/known")));
    }
    // Bitbucket hook UUIDs carry braces. A raw brace is an illegal URL character (the HTTP client refuses it before
    // anything is sent), so the path must carry them percent-encoded. Found on dev: updates and deletes failed.
    private static final String BRACED = "{f629a1ec-400a-4fb7-a219-a39125545da0}";
    private static final String BRACED_PATH = "/%7Bf629a1ec-400a-4fb7-a219-a39125545da0%7D";
    @Test void updatingAHookWhoseUuidHasBracesSendsThemEncoded() {
        entity.setWebhookSecret("stable-secret");String path="/repositories/team/repo/hooks";
        list(path,"{\"values\":["+hook(BRACED,CALLBACK)+"]}");stubFor(put(urlEqualTo(path+BRACED_PATH)).willReturn(okJson("{\"uuid\":\""+BRACED+"\"}")));
        var result=api.upsertHook("repo","https://wt.example",List.of("pullrequest:created","pullrequest:updated"),false,BRACED,false);
        assertEquals("UPDATED",result.outcome());assertEquals(BRACED,result.uuid());
        verify(putRequestedFor(urlEqualTo(path+BRACED_PATH)).withRequestBody(matchingJsonPath("$.active",equalTo("false"))));
    }
    @Test void deletingAHookWhoseUuidHasBracesSendsThemEncoded() {
        String path="/repositories/team/repo/hooks";
        list(path,"{\"values\":["+hook(BRACED,CALLBACK)+"]}");stubFor(delete(urlEqualTo(path+BRACED_PATH)).willReturn(aResponse().withStatus(204)));
        api.deleteHook("repo","https://wt.example",BRACED);
        verify(1,deleteRequestedFor(urlEqualTo(path+BRACED_PATH)));
    }
    @Test void foreignHooksCannotBeEditedOrDeleted() {
        String path="/repositories/team/repo/hooks";list(path,"{\"values\":["+hook("foreign","https://other.example/hook")+"]}");
        assertThrows(IllegalArgumentException.class,()->api.upsertHook("repo","https://wt.example",List.of("pullrequest:created"),true,"foreign",false));
        assertThrows(IllegalArgumentException.class,()->api.deleteHook("repo","https://wt.example","foreign"));
        verify(0,putRequestedFor(anyUrl()));verify(0,deleteRequestedFor(anyUrl()));
    }
    @Test void delete404AndAlreadyAbsentAreIdempotent() {
        String path="/repositories/team/repo/hooks";list(path,"{\"values\":["+hook("owned",CALLBACK)+"]}");stubFor(delete(urlEqualTo(path+"/owned")).willReturn(notFound()));
        api.deleteHook("repo","https://wt.example","owned");list(path,"{\"values\":[]}");api.deleteHook("repo","https://wt.example","owned");verify(1,deleteRequestedFor(urlEqualTo(path+"/owned")));
    }
    @Test void hookLimitPreventsCreation() {
        String path="/repositories/team/repo/hooks";var values=new ArrayList<String>();for(int i=0;i<50;i++)values.add(hook("other"+i,"https://other.example/"+i));
        list(path,"{\"values\":["+String.join(",",values)+"]}");var ex=assertThrows(BBWebhookException.class,()->api.upsertHook("repo","https://wt.example",List.of("pullrequest:created"),true,null,false));
        assertEquals("LIMIT",ex.getCode());verify(0,postRequestedFor(anyUrl()));
    }
    @Test void mutationRateLimitAndErrorsAreTypedAndRedacted() {
        String path="/repositories/team/repo/hooks";list(path,"{\"values\":[]}");
        stubFor(post(urlEqualTo(path)).willReturn(aResponse().withStatus(429).withHeader("Retry-After","37").withBody("PRIVATE-SECRET")));
        var ex=assertThrows(BBWebhookException.class,()->api.upsertHook("repo","https://wt.example",List.of("pullrequest:created"),true,null,false));assertEquals(37,ex.getRetryAfterSeconds());assertFalse(ex.getMessage().contains("PRIVATE-SECRET"));
    }
    @Test void periodsAreValidButDotPathSegmentsAreRejected() {
        assertTrue(entity.makeRepoHooksUrl(".test.repo").endsWith("/.test.repo/hooks"));
        assertThrows(IllegalArgumentException.class,()->entity.makeRepoHooksUrl("."));assertThrows(IllegalArgumentException.class,()->entity.makeRepoHooksUrl(".."));
    }

}
