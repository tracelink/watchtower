package com.tracelink.appsec.watchtower.core.scan.code;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.mock.MockCustomRuleDto;
import com.tracelink.appsec.watchtower.core.module.scanner.ICodeScanner;
import com.tracelink.appsec.watchtower.core.rule.RuleDto;
import com.tracelink.appsec.watchtower.core.rule.RulePriority;
import com.tracelink.appsec.watchtower.core.rule.RuleRevision;
import com.tracelink.appsec.watchtower.core.rule.RuleState;
import com.tracelink.appsec.watchtower.core.ruleset.RulesetDto;
import com.tracelink.appsec.watchtower.core.scan.code.report.CodeScanReport;

class CodeScanExecutionSnapshotTest {
	static class Definition extends MockCustomRuleDto {
		String pattern = "private-source-marker";
		@Override protected RuleRevision executableDefinition() {
			return RuleRevision.definition("test", "v1").field("pattern", pattern);
		}
	}

	static class Scanner implements ICodeScanner {
		EngineExecutionIdentity identity = new EngineExecutionIdentity("test-engine", "1.0", "a".repeat(64), true);
		@Override public EngineExecutionIdentity getExecutionIdentity(CodeScanConfig config) { return identity; }
		@Override public List<Class<? extends RuleDto>> getSupportedRuleClass() { return List.of(Definition.class); }
		@Override public CodeScanReport scan(CodeScanConfig config) { return new CodeScanReport(); }
	}

	private Definition definition(String name, long id) {
		Definition rule = new Definition();
		rule.setId(id);
		rule.setName(name);
		rule.setPriority(RulePriority.HIGH);
		return rule;
	}

	private RulesetDto ruleset(Definition... rules) {
		RulesetDto dto = new RulesetDto();
		dto.setId(10L);
		dto.setName("Selected");
		dto.setBlockingLevel(RulePriority.MEDIUM);
		dto.setRules(Set.of(rules));
		return dto;
	}

	@Test void aRuleThatCouldNotRunIsRecordedAsThatRuleFailingAndTheScanReadsAsPartialByRuleNotByEngine() {
		var scanner = new Scanner();
		var snapshot = capture(ruleset(definition("kept", 1), definition("broken", 2)), scanner).withOutcome(scanner, "RAN");

		var marked = snapshot.withFailedRules(scanner, List.of("broken", "not-in-this-ruleset"));

		assertEquals("RAN", marked.engines().getFirst().status());
		assertEquals("FAILED", marked.rules().stream().filter(r -> "broken".equals(r.name())).findFirst().orElseThrow().coverage());
		assertNotEquals("FAILED", marked.rules().stream().filter(r -> "kept".equals(r.name())).findFirst().orElseThrow().coverage());
		var assessment = com.tracelink.appsec.watchtower.core.scan.presentation.ScanAssessment.of(
				com.tracelink.appsec.watchtower.core.scan.ScanStatus.DONE, marked, List.of());
		assertEquals("INCOMPLETE", assessment.completeness());
		assertEquals(List.of("broken failed."), assessment.reasons(), "the rule is named; the scanner is not blamed");
		assertSame(snapshot, snapshot.withFailedRules(scanner, List.of()), "nothing to mark changes nothing");
		assertSame(snapshot, snapshot.withFailedRules(scanner, null));
	}

	private CodeScanExecutionSnapshot capture(RulesetDto rules, ICodeScanner... scanners) {
		CodeScanConfig config = new CodeScanConfig();
		config.setRuleset(rules);
		return CodeScanExecutionSnapshot.capture(rules, List.of(scanners), config);
	}

 @Test void disabledPolicyAndReenableNeverReuseOldEvidenceOrInvokeDisabledEngine(){
  var controls=org.mockito.Mockito.mock(com.tracelink.appsec.watchtower.core.module.ModuleControlService.class);
  org.mockito.Mockito.when(controls.policy("test")).thenReturn(new com.tracelink.appsec.watchtower.core.module.ModuleControlService.Policy("test",true,0));
  var delegate=new Scanner();var scanner=new com.tracelink.appsec.watchtower.core.module.ControlledCodeScanner("test",delegate,controls);
  var rules=ruleset(definition("selected",1));var original=capture(rules,scanner);assertTrue(original.isReusable());
  assertEquals(delegate.getClass().getName(),original.engines().getFirst().scanner());
  org.mockito.Mockito.when(controls.policy("test")).thenReturn(new com.tracelink.appsec.watchtower.core.module.ModuleControlService.Policy("test",false,1));
  assertTrue(scanner.isDisabled());assertFalse(scanner.scan(new CodeScanConfig()).getErrors().isEmpty());
  var disabled=new com.tracelink.appsec.watchtower.core.module.ControlledCodeScanner("test",delegate,controls);
  var evidence=capture(rules,disabled);assertEquals("DISABLED",evidence.rules().getFirst().coverage());assertEquals("DISABLED",evidence.engines().getFirst().status());assertFalse(evidence.isReusable());
  org.mockito.Mockito.when(controls.policy("test")).thenReturn(new com.tracelink.appsec.watchtower.core.module.ModuleControlService.Policy("test",true,2));
  var restored=new com.tracelink.appsec.watchtower.core.module.ControlledCodeScanner("test",delegate,controls);assertNotEquals(original.fingerprint(),capture(rules,restored).fingerprint());assertTrue(scanner.isDisabled());scanner.prepareExecution();assertFalse(scanner.isDisabled());assertNotEquals(original.fingerprint(),capture(rules,scanner).fingerprint());
  assertFalse(original.withOutcome(scanner,"FAILED").isReusable());assertEquals("FAILED",original.withOutcome(scanner,"FAILED").rules().getFirst().coverage());
 }

	@Test void aScannerWithNoMatchingFilesCountsAsFinishedNotAsSkipped() {
		Scanner scanner = new Scanner();
		var captured = capture(ruleset(definition("selected", 1)), scanner);
		var notApplicable = captured.withOutcome(scanner, "NOT_APPLICABLE");
		assertEquals("NOT_APPLICABLE", notApplicable.engines().getFirst().status());
		assertEquals("NOT_APPLICABLE", notApplicable.rules().getFirst().coverage());
		assertTrue(notApplicable.isReusable());
		assertTrue(notApplicable.hasSuccessfulExecution());
		assertFalse(captured.withOutcome(scanner, "SKIPPED").hasSuccessfulExecution());
	}

	@Test void snapshotIsImmutableSourceFreeAndDoesNotTreatModuleSuccessAsRuleCoverage() {
		Definition rule = definition("original", 12);
		RulesetDto rules = ruleset(rule);
		Scanner scanner = new Scanner();
		var captured = capture(rules, scanner);
		var completed = captured.withOutcome(scanner, "RAN");
		assertTrue(captured.isReusable());
		assertFalse(captured.hasSuccessfulExecution());
		assertTrue(completed.hasSuccessfulExecution());
		assertEquals("UNKNOWN", completed.rules().getFirst().coverage());
		assertNull(completed.rules().getFirst().evaluatedOpportunities());
		String revision = completed.rules().getFirst().identity().revision();
		rule.pattern = "changed";
		rule.setName("renamed");
		rule.setPriority(RulePriority.LOW);
		rule.getStewardship().setState(RuleState.DEPRECATED);
		rules.setBlockingLevel(null);
		assertEquals("original", completed.rules().getFirst().name());
		assertEquals(revision, completed.rules().getFirst().identity().revision());
		assertEquals(RulePriority.HIGH, completed.rules().getFirst().priority());
		assertEquals(RuleState.ACTIVE, completed.rules().getFirst().state());
		assertEquals(RulePriority.MEDIUM, completed.blockingLevel());
		String json = CodeScanExecutionSnapshotCodec.encode(completed);
		assertFalse(json.contains("private-source-marker"));
		assertFalse(json.contains("evaluatedOpportunities\":1"));
		assertEquals(completed, CodeScanExecutionSnapshotCodec.decode(json));
		assertThrows(UnsupportedOperationException.class, () -> completed.rules().clear());
		assertEquals(99L, completed.reusedFrom(99).reusedFromScanId());
		assertNotEquals("unknown", completed.engineKey(scanner.getClass().getName()));
		assertEquals("unknown", completed.engineKey("missing"));
	}

	@Test void contentPolicyLifecycleAndEngineConfigurationInvalidateReuseWhileOrderDoesNot() {
		Definition first = definition("first", 1);
		Definition second = definition("second", 2);
		RulesetDto rules = ruleset(first, second);
		Scanner scanner = new Scanner();
		String original = capture(rules, scanner).fingerprint();
		rules.setRules(Set.of(second, first));
		assertEquals(original, capture(rules, scanner).fingerprint());
		first.pattern = "edited-under-the-same-name";
		assertNotEquals(original, capture(rules, scanner).fingerprint());
		first.pattern = "private-source-marker";
		first.setPriority(RulePriority.LOW);
		assertNotEquals(original, capture(rules, scanner).fingerprint());
		first.setPriority(RulePriority.HIGH);
		first.getStewardship().setState(RuleState.DEPRECATED);
		assertNotEquals(original, capture(rules, scanner).fingerprint());
		first.getStewardship().setState(RuleState.ACTIVE);
		rules.setBlockingLevel(null);
		assertNotEquals(original, capture(rules, scanner).fingerprint());
		rules.setBlockingLevel(RulePriority.MEDIUM);
		scanner.identity = new EngineExecutionIdentity("test-engine", "2.0", "a".repeat(64), true);
		assertNotEquals(original, capture(rules, scanner).fingerprint());
		scanner.identity = new EngineExecutionIdentity("test-engine", "1.0", "b".repeat(64), true);
		assertNotEquals(original, capture(rules, scanner).fingerprint());
	}

	@Test void unknownUnsupportedSkippedAndFailedExecutionsCannotSupplyReusableResults() {
		RulesetDto rules = ruleset(definition("rule", 1));
		Scanner scanner = new Scanner();
		var unsupported = capture(rules);
		assertEquals("UNSUPPORTED", unsupported.rules().getFirst().coverage());
		assertFalse(unsupported.isReusable());
		var selected = capture(rules, scanner);
		assertFalse(selected.withOutcome(scanner, "FAILED").isReusable());
		assertFalse(selected.withOutcome(scanner, "SKIPPED").isReusable());
		assertEquals("SKIPPED", selected.withOutcome(scanner, "SKIPPED").rules().getFirst().coverage());
		scanner.identity = null;
		assertFalse(capture(rules, scanner).isReusable());
		ICodeScanner defaultScanner = new ICodeScanner() {
			@Override public List<Class<? extends RuleDto>> getSupportedRuleClass() { return List.of(Definition.class); }
			@Override public CodeScanReport scan(CodeScanConfig config) { return new CodeScanReport(); }
		};
		assertFalse(capture(rules, defaultScanner).isReusable());
		assertFalse(EngineExecutionIdentity.unknown("external").isReusable());
		assertFalse(new EngineExecutionIdentity("external", "", "a".repeat(64), true).isReusable());
		assertFalse(new EngineExecutionIdentity("external", "1", "invalid", true).isReusable());
		assertFalse(new EngineExecutionIdentity("external", "1", "a".repeat(64), false).isReusable());
		assertFalse(new EngineExecutionIdentity(null, "1", "a".repeat(64), true).isReusable());
		var ambiguous = capture(rules, scanner, new Scanner());
		assertFalse(ambiguous.isReusable(), "ambiguous scanner ownership stays unknown");
		assertEquals("unknown", ambiguous.engineKey(scanner.getClass().getName()));
		assertEquals("UNKNOWN", ambiguous.withOutcome(scanner, "RAN").engines().getFirst().status());
		var missingEngine = new CodeScanExecutionSnapshot(1, 10L, "Selected", RulePriority.MEDIUM,
				selected.rules(), List.of(), null);
		assertFalse(missingEngine.isReusable());
		var unknownIdentity = new CodeScanExecutionSnapshot.EngineExecution("external", null, "RAN");
		assertFalse(unknownIdentity.identity().isReusable());
	}

	@Test void legacyAndFutureSnapshotsRemainExplicitlyUnknownAndBounded() {
		assertNull(CodeScanExecutionSnapshotCodec.decode(null));
		assertNull(CodeScanExecutionSnapshotCodec.decode(" "));
		assertNull(CodeScanExecutionSnapshotCodec.encode(null));
		var legacy = CodeScanExecutionSnapshotCodec.decode("{\"futureField\":true}");
		assertFalse(legacy.isReusable());
		assertTrue(legacy.rules().isEmpty());
		assertThrows(IllegalArgumentException.class, () -> CodeScanExecutionSnapshotCodec.decode("broken"));
		assertThrows(IllegalArgumentException.class, () -> CodeScanExecutionSnapshotCodec.decode("\u20ac".repeat(3_000_000)));
		var large = new CodeScanExecutionSnapshot(1, null, "x".repeat(9_000_000), null, List.of(), List.of(), null);
		assertThrows(IllegalArgumentException.class, () -> CodeScanExecutionSnapshotCodec.encode(large));
	}

	@Test void javaArtifactEvidenceTracksBytecodeAndSettingsWithoutPathsOrApplicationResources(
			@org.junit.jupiter.api.io.TempDir java.nio.file.Path temporary) throws Exception {
		var classes = java.nio.file.Files.createDirectory(temporary.resolve("classes"));
		java.nio.file.Files.writeString(classes.resolve("A.class"), "first implementation");
		java.nio.file.Files.writeString(classes.resolve("B.class"), "second implementation");
		String original = JavaEngineExecutionIdentity.hashClasses(classes.toUri().toURL());
		java.nio.file.Files.writeString(classes.resolve("application.yaml"), "credentials: private-marker");
		assertEquals(original, JavaEngineExecutionIdentity.hashClasses(classes.toUri().toURL()));
		var catalog = java.nio.file.Files.createDirectory(classes.resolve("rules")).resolve("catalog.xml");
		java.nio.file.Files.writeString(catalog, "<rules>first</rules>");
		var prefixes = Set.of("rules/");
		String withResources = JavaEngineExecutionIdentity.readArtifact(classes.toUri().toURL(), prefixes, false).hash();
		var jar = temporary.resolve("engine.jar");
		try (var output = new java.util.jar.JarOutputStream(java.nio.file.Files.newOutputStream(jar))) {
			for (String name : List.of("B.class", "application.yaml", "A.class", "rules/catalog.xml")) {
				output.putNextEntry(new java.util.jar.JarEntry(name));
				output.write(java.nio.file.Files.readAllBytes(classes.resolve(name)));
				output.closeEntry();
			}
		}
		assertEquals(original, JavaEngineExecutionIdentity.hashClasses(jar.toUri().toURL()));
		assertEquals(withResources, JavaEngineExecutionIdentity.readArtifact(jar.toUri().toURL(), prefixes, false).hash());
		java.nio.file.Files.writeString(catalog, "<rules>changed</rules>");
		assertNotEquals(withResources, JavaEngineExecutionIdentity.readArtifact(classes.toUri().toURL(), prefixes, false).hash());
		assertEquals(original, JavaEngineExecutionIdentity.hashClasses(classes.toUri().toURL()));
		assertClasspathOrder(classes.toUri().toURL(), jar.toUri().toURL());
		var manifest = new java.util.jar.Manifest();
		manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
		manifest.getMainAttributes().putValue("Multi-Release", "true");
		var manifestJar = temporary.resolve("manifest.jar");
		writeArtifact(manifestJar, manifest, classes);
		assertNotEquals(original, JavaEngineExecutionIdentity.hashClasses(manifestJar.toUri().toURL()));
		manifest.getMainAttributes().putValue("Multi-Release", "false");
		manifest.getMainAttributes().putValue("Sealed", "true");
		writeArtifact(manifestJar, manifest, classes);
		assertNotEquals(original, JavaEngineExecutionIdentity.hashClasses(manifestJar.toUri().toURL()));
		manifest.getMainAttributes().putValue("Class-Path", "private/dependency.jar");
		writeArtifact(manifestJar, manifest, classes);
		assertThrows(java.io.IOException.class, () -> JavaEngineExecutionIdentity.hashClasses(manifestJar.toUri().toURL()));
		var artifact = JavaEngineExecutionIdentity.readArtifact(jar.toUri().toURL());
		artifact.requireClass("A.class");
		assertThrows(java.io.IOException.class, () -> artifact.requireClass("nested/Engine.class"));
		assertEquals(original, JavaEngineExecutionIdentity.hashClasses(
				new java.net.URL("jar:" + jar.toUri() + "!/")));
		java.nio.file.Files.writeString(classes.resolve("A.class"), "changed implementation");
		assertNotEquals(original, JavaEngineExecutionIdentity.hashClasses(classes.toUri().toURL()));
		var empty = java.nio.file.Files.createDirectory(temporary.resolve("empty"));
		assertThrows(java.io.IOException.class,
				() -> JavaEngineExecutionIdentity.hashClasses(empty.toUri().toURL()));
		java.nio.file.Files.createSymbolicLink(classes.resolve("linked.class"), classes.resolve("A.class"));
		assertThrows(java.io.IOException.class,
				() -> JavaEngineExecutionIdentity.hashClasses(classes.toUri().toURL()));

		Scanner scanner = new Scanner();
		CodeScanConfig config = new CodeScanConfig();
		var identity = JavaEngineExecutionIdentity.capture("java-test", scanner, config, RuleRevision.class);
		assertTrue(identity.isReusable());
		config.setWorkingDirectory(temporary);
		config.setRepositoryName("private-marker");
		config.setBenchmarkEnabled(true);
		assertEquals(identity, JavaEngineExecutionIdentity.capture("java-test", scanner, config, RuleRevision.class));
		String originalJarVersion = System.getProperty("jdk.util.jar.version");
		try {
			System.setProperty("jdk.util.jar.version", "8");
			assertNotEquals(identity, JavaEngineExecutionIdentity.capture("java-test", scanner, config, RuleRevision.class),
					"The selected multi-release JAR version can change runtime class resolution");
		} finally {
			if (originalJarVersion == null) System.clearProperty("jdk.util.jar.version");
			else System.setProperty("jdk.util.jar.version", originalJarVersion);
		}
		config.setThreads(config.getThreads() + 1);
		assertNotEquals(identity, JavaEngineExecutionIdentity.capture("java-test", scanner, config, RuleRevision.class));
		assertNotEquals(identity, JavaEngineExecutionIdentity.capture("java-test", new Scanner() {
			@Override public Set<String> getExcludedFolders() { return Set.of("node_modules"); }
		}, new CodeScanConfig(), RuleRevision.class));
		config.setRuleset(ruleset(new Definition() {}));
		assertFalse(JavaEngineExecutionIdentity.capture("java-test", scanner, config, RuleRevision.class).isReusable());
		assertFalse(JavaEngineExecutionIdentity.capture("java-test", scanner, config, String.class).isReusable());
		assertFalse(JavaEngineExecutionIdentity.capture("java-test", scanner, config).isReusable());
		assertFalse(new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(identity).contains("private-marker"));
		assertFalse(identity.version().contains(temporary.toString()));
	}

	private void writeArtifact(java.nio.file.Path jar, java.util.jar.Manifest manifest,
			java.nio.file.Path classes) throws Exception {
		try (var output = new java.util.jar.JarOutputStream(java.nio.file.Files.newOutputStream(jar), manifest)) {
			for (String name : List.of("A.class", "B.class")) {
				output.putNextEntry(new java.util.jar.JarEntry(name));
				output.write(java.nio.file.Files.readAllBytes(classes.resolve(name)));
				output.closeEntry();
			}
		}
	}

	private void assertClasspathOrder(java.net.URL first, java.net.URL second) throws Exception {
		var core = RuleRevision.class.getProtectionDomain().getCodeSource().getLocation();
		try (var ordered = new java.net.URLClassLoader(new java.net.URL[] {core, first, second}, ClassLoader.getPlatformClassLoader());
				var reversed = new java.net.URLClassLoader(new java.net.URL[] {core, second, first}, ClassLoader.getPlatformClassLoader())) {
			Class<?> anchor = ordered.loadClass(RuleRevision.class.getName());
			Class<?> reversedAnchor = reversed.loadClass(RuleRevision.class.getName());
			var firstEvidence = JavaEngineExecutionIdentity.captureClasspath("java-test", new Scanner(),
					new CodeScanConfig(), ordered, Set.of("rules/"), anchor);
			var reversedEvidence = JavaEngineExecutionIdentity.captureClasspath("java-test", new Scanner(),
					new CodeScanConfig(), reversed, Set.of("rules/"), reversedAnchor);
			assertTrue(firstEvidence.isReusable());
			assertTrue(reversedEvidence.isReusable());
			assertNotEquals(firstEvidence, reversedEvidence);
			assertFalse(JavaEngineExecutionIdentity.captureClasspath("java-test", new Scanner(), new CodeScanConfig(),
					new ClassLoader(ordered) {}, Set.of(), anchor).isReusable());
			assertFalse(JavaEngineExecutionIdentity.captureClasspath("java-test", new Scanner(), new CodeScanConfig(),
					ordered, Set.of(), CodeScanExecutionSnapshotTest.class).isReusable());
			assertFalse(JavaEngineExecutionIdentity.captureClasspath("java-test", new Scanner(), new CodeScanConfig(),
					null, Set.of(), anchor).isReusable());
		}
	}
}
