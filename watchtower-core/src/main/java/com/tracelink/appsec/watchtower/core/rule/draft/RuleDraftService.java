package com.tracelink.appsec.watchtower.core.rule.draft;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.assistant.AssistantText;
import com.tracelink.appsec.watchtower.core.module.designer.RuleDraftData;
import com.tracelink.appsec.watchtower.core.rule.RuleDesignerService;

/**
 * Rules drafted for a person to review in a designer. A draft is private to the person who asked for it, holds
 * only rule text and small synthetic examples, expires, and is never a rule: the person saves it in the designer.
 * Everything is checked on the way in, whatever wrote it: sizes, text that looks like a secret, and, for ESLint,
 * code that reaches outside the rule.
 */
@Service
public class RuleDraftService {
	/** The scanners that have a designer a draft can be opened in. */
	public static final Set<String> ENGINES = Set.of("opengrep", "regex", "pmd", "json", "eslint");
	static final long TTL_MILLIS = 30L * 24 * 60 * 60 * 1000;
	static final int MAX_OPEN_PER_PERSON = 50, MAX_NAME = 100, MAX_MESSAGE = 500, MAX_RATIONALE = 500, MAX_SOURCE = 120,
			MAX_LANGUAGE = 32, MAX_EXTENSION = 32, MAX_TEXT_BYTES = 8192, MAX_ESLINT_BYTES = 4096;
	private static final Pattern ID = Pattern.compile("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
	private static final Pattern CWE = Pattern.compile("CWE-[1-9][0-9]{0,8}");
	private static final Pattern CWE_LIST = Pattern.compile("CWE-[1-9][0-9]{0,8}(?:,CWE-[1-9][0-9]{0,8}){0,9}");
	/**
	 * Words an ESLint rule has no business using: loading modules, the process, the file system, the network,
	 * timers, dynamic code and the ways to reach the global object. The rule is also shown to its author before
	 * it ever runs; this stops the obvious attempts early.
	 */
	private static final Pattern ESLINT_FORBIDDEN = Pattern.compile("\\b(?:require|import|export|process|child_process|fs|eval|Function|fetch"
			+ "|XMLHttpRequest|WebSocket|globalThis|global|window|document|setTimeout|setInterval|setImmediate|Buffer|module|exports"
			+ "|__dirname|__filename|constructor|prototype|Reflect|Proxy|Worker|Atomics)\\b");

	private final RuleDraftRepository drafts;
	private final Clock clock;
	private RuleDesignerService designers;

	@Autowired
	public RuleDraftService(RuleDraftRepository drafts) {
		this(drafts, Clock.systemUTC());
	}

	RuleDraftService(RuleDraftRepository drafts, Clock clock) {
		this.drafts = drafts;
		this.clock = clock;
	}

	/** The designers, so each engine can check its own kind of rule; without them only the common checks run. */
	@Autowired(required = false)
	public void setDesigners(RuleDesignerService designers) {
		this.designers = designers;
	}

	/** Stores a draft for {@code owner} and returns it with its id. */
	@Transactional
	public RuleDraftData create(String owner, RuleDraftData draft) {
		if (owner == null || owner.isBlank()) {
			throw new IllegalArgumentException("A draft needs a person to belong to.");
		}
		RuleDraftData clean = checked(draft);
		long now = clock.millis();
		drafts.deleteByExpiresAtLessThan(now);
		if (drafts.countByCreatedByAndStatusAndExpiresAtGreaterThan(owner, RuleDraftEntity.OPEN, now) >= MAX_OPEN_PER_PERSON) {
			throw new IllegalArgumentException("You have " + MAX_OPEN_PER_PERSON + " open drafts. Discard some first.");
		}
		String id = UUID.randomUUID().toString();
		drafts.save(new RuleDraftEntity(id, owner, clean, now, now + TTL_MILLIS));
		return clean.withId(id);
	}

	/** The person's own open draft for this scanner, or nothing when it is missing, someone else's, used or expired. */
	@Transactional(readOnly = true)
	public Optional<RuleDraftData> open(String id, String owner, String engine) {
		return find(id, owner).filter(entity -> entity.getEngine().equalsIgnoreCase(engine == null ? "" : engine))
				.map(RuleDraftEntity::toData);
	}

	/** Discards the person's own open draft. @return whether there was one */
	@Transactional
	public boolean discard(String id, String owner) {
		Optional<RuleDraftEntity> found = find(id, owner);
		found.ifPresent(entity -> entity.finish(RuleDraftEntity.DISCARDED, null));
		return found.isPresent();
	}

	/** Records that the person saved a rule from the draft, so it is not offered again. */
	@Transactional
	public void markUsed(String id, String owner, String ruleName) {
		find(id, owner).ifPresent(entity -> entity.finish(RuleDraftEntity.USED, ruleName));
	}

	/** The draft as the person's own open one, for the save hook to read the CWE from. */
	@Transactional(readOnly = true)
	public Optional<RuleDraftData> ownedOpen(String id, String owner) {
		return find(id, owner).map(RuleDraftEntity::toData);
	}

	private Optional<RuleDraftEntity> find(String id, String owner) {
		if (id == null || owner == null || !ID.matcher(id).matches()) {
			return Optional.empty();
		}
		return drafts.findById(id).filter(entity -> entity.getCreatedBy().equals(owner)).filter(entity -> entity.isOpenAt(clock.millis()));
	}

	private RuleDraftData checked(RuleDraftData draft) {
		if (draft == null) {
			throw new IllegalArgumentException("There is no draft to store.");
		}
		String engine = draft.engine() == null ? "" : draft.engine().strip().toLowerCase(Locale.ROOT);
		if (!ENGINES.contains(engine)) {
			throw new IllegalArgumentException("Drafts can be made for " + String.join(", ", ENGINES.stream().sorted().toList()) + ".");
		}
		String name = required(draft.name(), "name", MAX_NAME);
		String message = required(draft.message(), "message", MAX_MESSAGE);
		if (draft.priority() < 1 || draft.priority() > 6) {
			throw new IllegalArgumentException("The priority must be from 1 to 6.");
		}
		String cwe = blankToNull(draft.cwe());
		String secondary = blankToNull(draft.secondaryCwes());
		if (cwe != null && !CWE.matcher(cwe).matches() || secondary != null && !CWE_LIST.matcher(secondary).matches()
				|| secondary != null && cwe == null) {
			throw new IllegalArgumentException("The CWEs must look like CWE-79, and secondary ones need a primary one.");
		}
		String definition = bounded(draft.definition(), "rule", engine.equals("eslint") ? MAX_ESLINT_BYTES : MAX_TEXT_BYTES, true);
		if (engine.equals("eslint") && ESLINT_FORBIDDEN.matcher(definition).find()) {
			throw new IllegalArgumentException("An ESLint rule may only inspect the code it is given; this one reaches outside it.");
		}
		RuleDraftData clean = new RuleDraftData(null, engine, optional(draft.language(), "language", MAX_LANGUAGE), name, message,
				draft.priority(), cwe, secondary, definition, optional(draft.fileExtension(), "file extension", MAX_EXTENSION),
				bounded(draft.vulnerableSnippet(), "vulnerable example", MAX_TEXT_BYTES, false),
				bounded(draft.safeSnippet(), "safe example", MAX_TEXT_BYTES, false),
				optional(draft.rationale(), "rationale", MAX_RATIONALE), optional(draft.sourceLabel(), "source", MAX_SOURCE));
		String problem = designers == null ? null : designers.problemWithDraft(engine, clean);
		if (problem != null) {
			throw new IllegalArgumentException(problem);
		}
		return clean;
	}

	private static String required(String value, String what, int max) {
		String text = optional(value, what, max);
		if (text == null) {
			throw new IllegalArgumentException("The " + what + " is missing.");
		}
		return text;
	}

	/** One line of plain text, at most {@code max} characters, and nothing that looks like a secret. */
	private static String optional(String value, String what, int max) {
		String text = blankToNull(value);
		if (text == null) {
			return null;
		}
		if (text.length() > max || text.chars().anyMatch(Character::isISOControl)) {
			throw new IllegalArgumentException("The " + what + " is too long or has control characters.");
		}
		requireNoSecret(text, what);
		return text;
	}

	/** Multi-line text of at most {@code maxBytes}, and nothing that looks like a secret. */
	private static String bounded(String value, String what, int maxBytes, boolean mandatory) {
		String text = value == null || value.isBlank() ? null : value.strip();
		if (text == null) {
			if (mandatory) {
				throw new IllegalArgumentException("The " + what + " is missing.");
			}
			return null;
		}
		if (text.getBytes(StandardCharsets.UTF_8).length > maxBytes) {
			throw new IllegalArgumentException("The " + what + " is longer than " + maxBytes + " bytes.");
		}
		requireNoSecret(text, what);
		return text;
	}

	private static void requireNoSecret(String text, String what) {
		if (!AssistantText.redact(text).equals(text)) {
			throw new IllegalArgumentException("The " + what + " looks like it contains a secret, so it was not stored.");
		}
	}

	private static String blankToNull(String value) {
		return value == null || value.isBlank() ? null : value.strip();
	}
}
