package com.tracelink.appsec.module.awssecurity;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import com.tracelink.appsec.watchtower.core.scan.code.*;
import com.tracelink.appsec.watchtower.core.scan.code.report.ProviderFindingDetails.Location;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.*;
import com.tracelink.appsec.watchtower.core.scan.code.scm.pr.bypass.*;
import com.tracelink.appsec.module.awssecurity.AwsPrDecision.*;

class AwsPrDecisionTest {
    private final AwsSecuritySnapshot snapshot=AwsTestSupport.snapshot("pr",CodeScanType.PULL_REQUEST);
    private AwsSecurityArtifact.Occurrence finding(String severity,boolean anchored) {
        var details=new AwsSecurityFindingMapper().map(AwsSecurityImporterTest.finding("id").toBuilder().riskLevel(severity).build(),snapshot,"review","job");
        return new AwsSecurityArtifact.Occurrence("key",details,anchored?List.of(new Location("src/b.java",10,10,"changed")):List.of());
    }
    private AwsSecurityArtifact.Occurrence finding(String severity,String confidence,boolean anchored) {
        var details=new AwsSecurityFindingMapper().map(AwsSecurityImporterTest.finding("id").toBuilder().riskLevel(severity).confidence(confidence).build(),snapshot,"review","job");
        return new AwsSecurityArtifact.Occurrence("key",details,anchored?List.of(new Location("src/b.java",10,10,"changed")):List.of());
    }
    @Test void onlyAHighConfidenceFindingCanBlock() {
        assertEquals(Decision.BLOCK,AwsPrDecision.decide(snapshot,List.of(finding("CRITICAL","HIGH",true)),true,false,null,FailurePolicy.KEEP_INCOMPLETE));
        for(var confidence:List.of("MEDIUM","LOW"))
            assertEquals(Decision.ALLOW,AwsPrDecision.decide(snapshot,List.of(finding("CRITICAL",confidence,true)),true,false,null,FailurePolicy.KEEP_INCOMPLETE),confidence);
    }
    @Test void aFindingThatWouldBlockButLacksConfidenceSaysWhy() {
        // Dev E2E P05: High findings did not block and the pull request comment gave no reason.
        assertEquals("not blocking: AWS confidence is Medium, High is needed",
            AwsPrDecision.notBlockingNote(finding("CRITICAL","MEDIUM",true).details(),snapshot));
        assertNull(AwsPrDecision.notBlockingNote(finding("CRITICAL","HIGH",true).details(),snapshot));
        assertNull(AwsPrDecision.notBlockingNote(finding("LOW","LOW",true).details(),snapshot),"below the blocking level it would not block anyway");
    }
    @Test void aLessConfidentFindingNeverMakesThePullRequestIncomplete() {
        assertEquals(Decision.ALLOW,AwsPrDecision.decide(snapshot,List.of(finding("CRITICAL","MEDIUM",false),finding("FUTURE","LOW",true)),true,false,null,FailurePolicy.KEEP_INCOMPLETE));
    }
    @Test void aFindingWithNoReadableConfidenceIsNotAssumedWeak() {
        assertTrue(AwsPrDecision.confident(finding("HIGH","HIGH",true).details()));
        assertEquals(Decision.BLOCK,AwsPrDecision.decide(snapshot,List.of(finding("HIGH","not a level!",true)),true,false,null,FailurePolicy.KEEP_INCOMPLETE));
    }
    @Test void criticalProjectsToHighAndRespectsExistingBypass() {
        assertEquals(Decision.BLOCK,AwsPrDecision.decide(snapshot,List.of(finding("CRITICAL",true)),true,false,null,FailurePolicy.KEEP_INCOMPLETE));
        var bypass=new ActiveBypass("engineer","accepted",1,Set.of(new BypassedFinding(snapshot.ruleName(),"src/b.java")));
        assertEquals(Decision.ALLOW,AwsPrDecision.decide(snapshot,List.of(finding("CRITICAL",true)),true,false,bypass,FailurePolicy.KEEP_INCOMPLETE));
    }
    @Test void belowThresholdDoesNotUnconditionallyBlock() {
        assertEquals(Decision.ALLOW,AwsPrDecision.decide(snapshot,List.of(finding("LOW",true)),true,false,null,FailurePolicy.KEEP_INCOMPLETE));
    }
    @Test void unknownSeverityUnprovenRelevanceAndPartialZeroCannotPass() {
        for(var finding:List.of(finding("FUTURE",true),finding("HIGH",false)))
            assertEquals(Decision.INCOMPLETE,AwsPrDecision.decide(snapshot,List.of(finding),true,false,null,FailurePolicy.PASS_ON_ERROR));
        assertEquals(Decision.INCOMPLETE,AwsPrDecision.decide(snapshot,List.of(),false,false,null,FailurePolicy.UNDECIDED));
    }
    @Test void headBaseAndOpenStateAllParticipateInFreshness() {
        var pr=new PullRequest("bb");pr.setState(PullRequestState.ACTIVE);pr.setCommitHash(snapshot.context().commit());pr.setBaseCommitHash(snapshot.context().baseCommit());pr.setDestinationBranch("main");
        assertTrue(AwsPrPublisher.fresh(snapshot.context(),pr));pr.setBaseCommitHash("moved");assertFalse(AwsPrPublisher.fresh(snapshot.context(),pr));
        pr.setBaseCommitHash(snapshot.context().baseCommit());pr.setState(PullRequestState.MERGED);assertFalse(AwsPrPublisher.fresh(snapshot.context(),pr));
    }
}
