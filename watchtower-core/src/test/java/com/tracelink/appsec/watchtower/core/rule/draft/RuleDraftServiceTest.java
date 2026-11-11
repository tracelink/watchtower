package com.tracelink.appsec.watchtower.core.rule.draft;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.tracelink.appsec.watchtower.core.assistant.R1Database;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;

/** Drafted rules: private to their author, bounded, screened for secrets, and gone after a while. */
class RuleDraftServiceTest {
	private static final Instant START = Instant.parse("2026-10-27T10:00:00Z");
	private final AtomicReference<Instant> now = new AtomicReference<>(START);
	private R1Database database;
	private RuleDraftService service;

	@BeforeEach
	void setUp() {
		database = new R1Database();
		Clock clock = new Clock() {
			@Override
			public java.time.ZoneId getZone() {
				return ZoneOffset.UTC;
			}

			@Override
			public Clock withZone(java.time.ZoneId zone) {
				return this;
			}

			@Override
			public Instant instant() {
				return now.get();
			}
		};
		service = database.service(new RuleDraftService(database.repository(RuleDraftRepository.class), clock));
	}

	@AfterEach
	void tearDown() {
		database.close();
	}

	private static RuleDraftData draft(String engine, String definition) {
		return new RuleDraftData(null, engine, "Java", "No string-built SQL", "Build queries with parameters.", 2, "CWE-89", "CWE-564",
				definition, ".java", "String q = \"select * from t where id=\" + id;", "String q = \"select * from t where id=?\";",
				"Concatenating input into SQL lets it change the query.", "Coverage gap: CWE-89 · Java");
	}

	@Test
	void aDraftIsStoredForItsAuthorAndOpensOnlyForThem() {
		var stored = service.create("alice", draft("regex", "select .*\\+"));

		assertThat(stored.id()).matches("[0-9a-f-]{36}");
		var opened = service.open(stored.id(), "alice", "regex");
		assertThat(opened).isPresent();
		assertThat(opened.get().name()).isEqualTo("No string-built SQL");
		assertThat(opened.get().vulnerableSnippet()).contains("select");
		assertThat(opened.get().cwe()).isEqualTo("CWE-89");
		assertThat(service.open(stored.id(), "bob", "regex")).as("someone else's draft").isEmpty();
		assertThat(service.open(stored.id(), "alice", "pmd")).as("the wrong designer").isEmpty();
		assertThat(service.open("not-an-id", "alice", "regex")).isEmpty();
		assertThat(service.open(null, "alice", "regex")).isEmpty();
	}

	@Test
	void aDraftExpiresAfterThirtyDays() {
		var stored = service.create("alice", draft("regex", "x+"));

		now.set(START.plus(Duration.ofDays(29)));
		assertThat(service.open(stored.id(), "alice", "regex")).isPresent();
		now.set(START.plus(Duration.ofDays(31)));
		assertThat(service.open(stored.id(), "alice", "regex")).isEmpty();
	}

	@Test
	void expiredDraftsAreRemovedWhenSomeoneMakesAnother() {
		var old = service.create("alice", draft("regex", "x+"));
		now.set(START.plus(Duration.ofDays(40)));

		service.create("alice", draft("regex", "y+"));

		assertThat(database.repository(RuleDraftRepository.class).findById(old.id())).isEmpty();
	}

	@Test
	void discardingOrUsingADraftClosesIt() {
		var first = service.create("alice", draft("regex", "x+"));
		var second = service.create("alice", draft("regex", "y+"));

		assertThat(service.discard(first.id(), "bob")).isFalse();
		assertThat(service.discard(first.id(), "alice")).isTrue();
		service.markUsed(second.id(), "alice", "No string-built SQL");

		assertThat(service.open(first.id(), "alice", "regex")).isEmpty();
		assertThat(service.open(second.id(), "alice", "regex")).isEmpty();
		assertThat(service.discard(first.id(), "alice")).as("already closed").isFalse();
	}

	@Test
	void aPersonCannotHaveMoreThanFiftyOpenDrafts() {
		for (int i = 0; i < RuleDraftService.MAX_OPEN_PER_PERSON; i++) {
			service.create("alice", draft("regex", "x" + i + "+"));
		}

		assertThatThrownBy(() -> service.create("alice", draft("regex", "y+"))).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("50");
		assertThat(service.create("bob", draft("regex", "y+")).id()).isNotBlank();
	}

	@Test
	void onlyScannersWithADesignerAreAccepted() {
		for (String refused : new String[] { "checkov", "advisory", "betterleaks", "", null }) {
			assertThatThrownBy(() -> service.create("alice", draft(refused, "x+"))).isInstanceOf(IllegalArgumentException.class);
		}
		assertThat(service.create("alice", draft("  REGEX ", "x+")).engine()).isEqualTo("regex");
	}

	@Test
	void sizesPrioritiesAndCwesAreChecked() {
		assertThatThrownBy(() -> service.create("alice", draft("regex", "x".repeat(8193)))).isInstanceOf(IllegalArgumentException.class)
				.hasMessageContaining("8192");
		assertThatThrownBy(() -> service.create("alice", draft("eslint", "create(c){}".concat(" ".repeat(10)).concat("x".repeat(4097)))))
				.isInstanceOf(IllegalArgumentException.class).hasMessageContaining("4096");
		assertThatThrownBy(() -> service.create("alice", new RuleDraftData(null, "regex", null, "n", "m", 0, null, null, "x+", null, null, null, null, null)))
				.hasMessageContaining("priority");
		assertThatThrownBy(() -> service.create("alice", new RuleDraftData(null, "regex", null, "n", "m", 3, "CWE-x", null, "x+", null, null, null, null, null)))
				.hasMessageContaining("CWE");
		assertThatThrownBy(() -> service.create("alice", new RuleDraftData(null, "regex", null, "n", "m", 3, null, "CWE-79", "x+", null, null, null, null, null)))
				.hasMessageContaining("primary");
		assertThatThrownBy(() -> service.create("alice", new RuleDraftData(null, "regex", null, "", "m", 3, null, null, "x+", null, null, null, null, null)))
				.hasMessageContaining("name");
		assertThatThrownBy(() -> service.create("alice", new RuleDraftData(null, "regex", null, "n", "m", 3, null, null, " ", null, null, null, null, null)))
				.hasMessageContaining("rule");
		assertThatThrownBy(() -> service.create("alice", new RuleDraftData(null, "regex", null, "n\nx", "m", 3, null, null, "x+", null, null, null, null, null)))
				.hasMessageContaining("control");
	}

	@Test
	void textThatLooksLikeASecretIsRefusedEverywhere() {
		var withSecret = new RuleDraftData(null, "regex", null, "n", "m", 3, null, null, "x+", null,
				"String password = \"hunter2hunter2\";", null, null, null);
		assertThatThrownBy(() -> service.create("alice", withSecret)).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("secret");
		var inRule = new RuleDraftData(null, "regex", null, "n", "m", 3, null, null, "AKIAABCDEFGHIJKLMNOP", null, null, null, null, null);
		assertThatThrownBy(() -> service.create("alice", inRule)).hasMessageContaining("secret");
		var inRationale = new RuleDraftData(null, "regex", null, "n", "m", 3, null, null, "x+", null, null, null, "token = abcdefgh12345", null);
		assertThatThrownBy(() -> service.create("alice", inRationale)).hasMessageContaining("secret");
	}

	@Test
	void anEslintRuleThatReachesOutsideTheCodeItIsGivenIsRefused() {
		for (String bad : new String[] { "create(c){ require('fs'); return {}; }", "create(c){ return { Program(){ process.exit(1); } }; }",
				"create(c){ eval('1'); return {}; }", "create(c){ new Function('return 1')(); return {}; }",
				"create(c){ fetch('http://x'); return {}; }", "create(c){ return globalThis.x; }" }) {
			assertThatThrownBy(() -> service.create("alice", draft("eslint", bad))).as(bad).isInstanceOf(IllegalArgumentException.class)
					.hasMessageContaining("reaches outside");
		}
		var fine = "create(context) { return { BinaryExpression(node) { if (node.operator === '==') { context.report({ node, messageId: 'unexpected' }); } } }; }";
		assertThat(service.create("alice", draft("eslint", fine)).engine()).isEqualTo("eslint");
		var importDeclaration = "create(context) { return { ImportDeclaration(node) { context.report({ node, messageId: 'x' }); } }; }";
		assertThat(service.create("alice", draft("eslint", importDeclaration)).id()).as("an AST node name is not the import keyword").isNotBlank();
	}

	@Test
	void theEnginesOwnCheckCanRefuseADraft() {
		var designers = mock(RuleDesignerService.class);
		when(designers.problemWithDraft(eq("regex"), any())).thenReturn("The regular expression does not compile.");
		service.setDesigners(designers);

		assertThatThrownBy(() -> service.create("alice", draft("regex", "("))).isInstanceOf(IllegalArgumentException.class)
				.hasMessage("The regular expression does not compile.");
	}
}
