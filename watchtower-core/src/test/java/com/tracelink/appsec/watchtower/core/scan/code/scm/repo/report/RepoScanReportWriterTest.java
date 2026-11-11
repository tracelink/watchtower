package com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.zip.GZIPInputStream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleExecutionIdentity;
import com.tracelink.appsec.watchtower.core.scan.code.CodeScanExecutionSnapshot;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanViolation;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportWriter.ReportContext;
import com.tracelink.appsec.watchtower.core.scan.code.scm.repo.report.RepoScanReportWriter.WrittenReport;

public class RepoScanReportWriterTest {

	private static final String SOURCE_LINE = "String token = \"wt-fake-" + "SECRET-123\";";

	@TempDir
	Path repo;

	@TempDir
	Path reports;

	private LocalRepoReportStore store;

	private RepoScanReportWriter writer;

	private final ReportContext context =
			new ReportContext(7, "bb label", "pay/api", "main", "abc123", "Default",
					Set.of("secret-rule"), complete());

 private static CodeScanExecutionSnapshot complete() {
  return new CodeScanExecutionSnapshot(1,1L,"Default",RulePriority.HIGH,List.of(),
   List.of(new CodeScanExecutionSnapshot.EngineExecution("regex",new com.tracelink.appsec.watchtower.core.scan.code.EngineExecutionIdentity("regex","1","a".repeat(64),true),"RAN")),null);
 }
 @Test void truncatedBaselineAndMissingOrFailedCoverageCannotClaimNewOrFixed() throws Exception {
  var prior=RepoReportCodec.decode(store.get(writer.write(context,List.of(report(violation("a",1,RulePriority.HIGH),violation("b",2,RulePriority.HIGH),violation("c",3,RulePriority.HIGH))),repo,Optional.empty()).reportKey()).orElseThrow());
  for (var candidate:List.of(prior,new RepoScanReport(4,6,"bb label","pay/api","main","old","Default",prior.findings(),List.of(),List.of(),2))) {
   var written=writer.write(context,List.of(report(violation("fresh",1,RulePriority.HIGH))),repo,Optional.of(candidate));
   Assertions.assertNull(written.newCount());Assertions.assertNull(written.fixedCount());Assertions.assertTrue(written.newFindings().isEmpty());
   var stored=RepoReportCodec.decode(store.get(written.reportKey()).orElseThrow());Assertions.assertFalse(stored.comparison().comparable());Assertions.assertFalse(stored.comparison().reasons().isEmpty());
  }
 }
 @Test void fixedTotalIncludesMoreThanOneThousandRemovedOccurrences() throws Exception {
  var findings=java.util.stream.IntStream.range(0,1501).mapToObj(i->new RepoScanReport.Finding("rule","High","File"+i,1,"message","key"+i,false,false)).toList();
  var previous=new RepoScanReport(5,6,"bb label","pay/api","main","old","Default",findings,List.of(),List.of(),findings.size(),complete()).withComparison(RepoScanReport.REPOSITORY_SCOPE,null);
  var written=writer.write(context,List.of(report()),repo,Optional.of(previous));
  Assertions.assertEquals(1501,written.fixedCount());Assertions.assertEquals(0,written.newCount());
  var stored=RepoReportCodec.decode(store.get(written.reportKey()).orElseThrow());Assertions.assertEquals(1000,stored.fixed().size());Assertions.assertTrue(stored.comparison().fixedSampleTruncated());Assertions.assertEquals(6,stored.comparison().baselineScanId());
 }
 @Test void coverageAndScopeChangesExplainUnavailableComparison() {
  var base=new RepoScanReport(5,1,"bb","repo","main","old","Default",List.of(),List.of(),List.of(),0,complete()).withComparison(RepoScanReport.REPOSITORY_SCOPE,null);
  for(String status:List.of("FAILED","SKIPPED","DISABLED","UNKNOWN")) {
   var snapshot=new CodeScanExecutionSnapshot(1,1L,"Default",RulePriority.HIGH,List.of(),List.of(new CodeScanExecutionSnapshot.EngineExecution("regex",complete().engines().getFirst().identity(),status)),null);
   var current=new RepoScanReport(5,2,"bb","repo","main","new","Default",List.of(),List.of(),List.of(),0,snapshot).withComparison(RepoScanReport.REPOSITORY_SCOPE,null);
   Assertions.assertFalse(ScanComparison.assess(current,base).comparable());
  }
  Assertions.assertTrue(ScanComparison.assess(base,base).comparable());
  Assertions.assertFalse(ScanComparison.assess(base.withComparison("other",null),base).comparable());
  Assertions.assertFalse(base.interpreted().comparison().comparable());
 }

	@BeforeEach
	public void setup() throws IOException {
		store = new LocalRepoReportStore(reports);
		writer = new RepoScanReportWriter(store, 2);
		Files.createDirectories(repo.resolve("src"));
		Files.writeString(repo.resolve("src/App.java"),
				"class App {\n  " + SOURCE_LINE + "\n  int other = 1;\n}\n");
	}

	private CodeScanReport report(CodeScanViolation... violations) {
		CodeScanReport report = new CodeScanReport();
		for (CodeScanViolation violation : violations) {
			report.addViolation(violation);
		}
		return report;
	}

	private CodeScanViolation violation(String rule, int line, RulePriority severity) {
		CodeScanViolation violation = new CodeScanViolation();
		violation.setViolationName(rule);
		violation.setLineNum(line);
		violation.setSeverity(severity);
		violation.setFileName(repo.resolve("src/App.java").toString());
		violation.setMessage(rule + " found");
		return violation;
	}

	@Test
	public void storedReportHoldsNoSourceCode() throws IOException {
		WrittenReport written = writer.write(context,
				List.of(report(violation("hardcoded-token", 2, RulePriority.HIGH))), repo,
				Optional.empty());

		byte[] stored = store.get(written.reportKey()).orElseThrow();
		String json = new String(new GZIPInputStream(new ByteArrayInputStream(stored))
				.readAllBytes(), StandardCharsets.UTF_8);
		Assertions.assertFalse(json.contains("SECRET-123"), "report must not contain code");
		Assertions.assertFalse(json.contains("String token"), "report must not contain code");
		Assertions.assertTrue(json.contains("src/App.java"));
		Assertions.assertEquals("reports/repository/bb_label/pay_api/7.json.gz",
				written.reportKey());
	}

	@Test
	public void manualReviewMatchesAreNotFindingsOfARepositoryScan() throws IOException {
		WrittenReport written = writer.write(context,
				List.of(report(violation("MCR Match: payments", 2, RulePriority.INFORMATIONAL),
						violation("hardcoded-token", 2, RulePriority.HIGH))),
				repo, Optional.empty());

		RepoScanReport stored = RepoReportCodec.decode(store.get(written.reportKey()).orElseThrow());
		Assertions.assertEquals(List.of("hardcoded-token"),
				stored.findings().stream().map(RepoScanReport.Finding::rule).toList());
		Assertions.assertEquals(1, stored.totalFindings());
		Assertions.assertEquals(Map.of("hardcoded-token", 1), written.ruleCounts());
	}

	@Test
	public void secretFingerprintsDoNotHashTheFlaggedLine() throws IOException {
		RepoScanReport.Finding secret = RepoReportCodec.decode(store.get(writer.write(context,
				List.of(report(violation("secret-rule", 2, RulePriority.HIGH))), repo,
				Optional.empty()).reportKey()).orElseThrow()).findings().get(0);

		Assertions.assertEquals(
				FindingFingerprint.of("secret-rule", "src/App.java", null, "secret-rule found"),
				secret.fingerprint());
		Assertions.assertNotEquals(FindingFingerprint.of("secret-rule", "src/App.java",
				SOURCE_LINE, "secret-rule found"), secret.fingerprint());
	}

	@Test
	public void duplicateSecretOccurrencesKeepDistinctKeysAndOriginalExecutionMetadata() throws IOException {
		RuleExecutionIdentity identity = new RuleExecutionIdentity(42L, "betterleaks", "a".repeat(64), "detector", null);
		CodeScanViolation first = violation("secret-rule", 2, RulePriority.INFORMATIONAL);
		CodeScanViolation second = violation("secret-rule", 3, RulePriority.INFORMATIONAL);
		for (var violation : List.of(first, second)) {
			violation.setRuleIdentity(identity);
			violation.setEffectiveBlocking(false);
			violation.setEngineFingerprint("b".repeat(64));
		}
		var snapshot = new CodeScanExecutionSnapshot(1, 1L, "Default", RulePriority.HIGH,
				List.of(), List.of(), null);
		var written = writer.write(context.withExecutionSnapshot(snapshot), List.of(report(first, second)),
				repo, Optional.empty());
		var stored = RepoReportCodec.decode(store.get(written.reportKey()).orElseThrow());
		Assertions.assertEquals(snapshot, stored.executionSnapshot());
		Assertions.assertEquals(2, stored.totalFindings());
		Assertions.assertEquals(stored.findings().get(0).fingerprint(), stored.findings().get(1).fingerprint());
		Assertions.assertNotEquals(stored.findings().get(0).findingKey(), stored.findings().get(1).findingKey());
		Assertions.assertNotEquals(RepoScanReport.createFindingKey(7, 0), RepoScanReport.createFindingKey(7, 0),
				"a retry must not repoint a saved occurrence reference to a different finding");
		for (var finding : stored.findings()) {
			Assertions.assertEquals(identity, finding.ruleIdentity());
			Assertions.assertEquals(false, finding.effectiveBlocking());
			Assertions.assertEquals("b".repeat(64), finding.engineFingerprint());
			Assertions.assertEquals(identity, finding.withNew(true).ruleIdentity());
		}
	}

	@Test
	public void oldReportJsonDoesNotInventIdentityOrPolicy() throws IOException {
		String json = """
				{"schema":1,"scanId":7,"findings":[{"rule":"old","severity":"High",
				"file":"App.java","line":1,"fingerprint":"old-fingerprint","isNew":false}]}
				""";
		var bytes = new java.io.ByteArrayOutputStream();
		try (var gzip = new java.util.zip.GZIPOutputStream(bytes)) {
			gzip.write(json.getBytes(StandardCharsets.UTF_8));
		}
		var old = RepoReportCodec.decode(bytes.toByteArray());
		Assertions.assertEquals(1, old.schema());
		Assertions.assertNull(old.executionSnapshot());
		Assertions.assertNull(old.findings().getFirst().ruleIdentity());
		Assertions.assertNull(old.findings().getFirst().engineFingerprint());
		Assertions.assertNull(old.findings().getFirst().effectiveBlocking());
		Assertions.assertNull(old.findings().getFirst().findingKey());
	}

	@Test
	public void firstScanIsABaselineWithNoNewOrFixedCounts() throws IOException {
		WrittenReport written = writer.write(context,
				List.of(report(violation("a", 2, RulePriority.HIGH),
						violation("b", 3, RulePriority.INFORMATIONAL))),
				repo, Optional.empty());

		Assertions.assertNull(written.newCount());
		Assertions.assertNull(written.fixedCount());
		Assertions.assertTrue(written.newFindings().isEmpty());
		Assertions.assertEquals(2, written.counts().total());
		Assertions.assertEquals(1L, written.metricCounts().get("a"));
		Assertions.assertFalse(written.metricCounts().containsKey("b"));
	}

	@Test
	public void comparesWithThePreviousReportDespiteLineMoves() throws IOException {
		RepoScanReport previous = RepoReportCodec.decode(store.get(writer.write(context,
				List.of(report(violation("a", 2, RulePriority.HIGH),
						violation("gone", 3, RulePriority.LOW))),
				repo, Optional.empty()).reportKey()).orElseThrow());
		// The flagged line moves down one line; rule "a" is the same finding
		Files.writeString(repo.resolve("src/App.java"),
				"class App {\n\n  " + SOURCE_LINE + "\n}\n");

		WrittenReport second = writer.write(context,
				List.of(report(violation("a", 3, RulePriority.HIGH),
						violation("fresh", 1, RulePriority.MEDIUM))),
				repo, Optional.of(previous));

		Assertions.assertEquals(1, second.newCount());
		Assertions.assertEquals(1, second.fixedCount());
		Assertions.assertEquals("fresh", second.newFindings().get(0).rule());
	}

	@Test
	public void capsStoredFindingsButKeepsExactCounts() throws IOException {
		WrittenReport written = writer.write(context,
				List.of(report(violation("low", 3, RulePriority.LOW),
						violation("high", 2, RulePriority.HIGH),
						violation("mid", 1, RulePriority.MEDIUM))),
				repo, Optional.empty());

		RepoScanReport stored =
				RepoReportCodec.decode(store.get(written.reportKey()).orElseThrow());
		Assertions.assertEquals(2, stored.findings().size());
		Assertions.assertEquals("high", stored.findings().get(0).rule());
		Assertions.assertTrue(stored.isTruncated());
		Assertions.assertEquals(3, written.counts().total());
	}

	@Test
	public void relativePathsStayInsideTheRepository() {
		Path root = repo.toAbsolutePath().normalize();
		Assertions.assertEquals("src/App.java",
				RepoScanReportWriter.relative(root, root.resolve("src/App.java").toString()));
		Assertions.assertEquals("App.java",
				RepoScanReportWriter.relative(root, "/elsewhere/App.java"));
		Assertions.assertEquals("a/b.txt", RepoScanReportWriter.relative(root, "./a/b.txt"));
	}

	@Test
	public void localStoreRefusesKeysOutsideItsDirectory() {
		Assertions.assertThrows(IOException.class,
				() -> store.put("../escape.json.gz", new byte[] {1}, "application/json"));
		Assertions.assertEquals("_", RepoReportStore.safe(".."));
	}
}
