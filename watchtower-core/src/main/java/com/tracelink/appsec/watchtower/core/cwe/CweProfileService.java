package com.tracelink.appsec.watchtower.core.cwe;

import java.time.Clock;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.tracelink.appsec.watchtower.core.rule.report.RuleReviewReport;

/**
 * The weaknesses that matter in this installation (the CWE profile) and what people decided about gaps in
 * their coverage. Adding a weakness is checked against the MITRE catalog; the pinned Top 25 can always be
 * added, so a fresh installation can start before the catalog is loaded.
 */
@Service
public class CweProfileService {
	static final int MAX_ENTRIES = 100, MAX_NOTE = 255;
	private static final Pattern CWE = Pattern.compile("(?i)(?:CWE-)?([1-9][0-9]{0,8})");

	/** One weakness in the profile. */
	public record Entry(int cwe, String label, String name, String priority, String note, boolean inCatalog) {
	}

	/** One decision about a weakness in a language column. */
	public record Decision(int cwe, String language, String decision, String note, String by, long at) {
	}

	private final CweProfileEntryRepository profile;
	private final CweGapDecisionRepository decisions;
	private final CweCatalogService catalog;
	private final Clock clock;
	/** The pinned Top 25, by number: always addable, and a source of names before the catalog is loaded. */
	private final Map<Integer, RuleReviewReport.Entry> top25;

	@Autowired
	public CweProfileService(CweProfileEntryRepository profile, CweGapDecisionRepository decisions, CweCatalogService catalog) {
		this(profile, decisions, catalog, Clock.systemUTC());
	}

	CweProfileService(CweProfileEntryRepository profile, CweGapDecisionRepository decisions, CweCatalogService catalog,
			Clock clock) {
		this.profile = profile;
		this.decisions = decisions;
		this.catalog = catalog;
		this.clock = clock;
		this.top25 = RuleReviewReport.Catalog.load().entries().stream()
				.collect(Collectors.toUnmodifiableMap(entry -> number(entry.id()).orElseThrow(), Function.identity()));
	}

	@Transactional(readOnly = true)
	public List<Entry> list() {
		return profile.findAll().stream()
				.sorted(Comparator.comparing((CweProfileEntryEntity e) -> e.getPriority()).thenComparingInt(CweProfileEntryEntity::getCweId))
				.map(this::view).toList();
	}

	/** Adds a weakness, or changes the priority and note of one already there. */
	@Transactional
	public Entry add(String cwe, String priority, String note, String actor) {
		int id = number(cwe).orElseThrow(() -> new IllegalArgumentException("Enter a CWE number, like CWE-79."));
		CweProfilePriority level = priorityOf(priority);
		String cleanNote = cleanNote(note);
		requireKnown(id);
		return view(store(id, level, cleanNote, actor));
	}

	/** Adds MITRE's Top 25 that are not there yet, in priority bands by rank; returns how many were added. */
	@Transactional
	public int addTop25(String actor) {
		int added = 0;
		for (RuleReviewReport.Entry entry : top25.values()) {
			int id = number(entry.id()).orElseThrow();
			if (!profile.existsById(id)) {
				store(id, CweProfilePriority.ofTop25Rank(entry.rank()), null, actor);
				added++;
			}
		}
		return added;
	}

	@Transactional
	public void remove(String cwe) {
		int id = number(cwe).orElseThrow(() -> new IllegalArgumentException("Enter a CWE number, like CWE-79."));
		decisions.deleteByCweId(id);
		profile.deleteById(id);
	}

	@Transactional
	public Decision decide(String cwe, String language, String decision, String note, String actor) {
		int id = number(cwe).orElseThrow(() -> new IllegalArgumentException("Enter a CWE number, like CWE-79."));
		if (!profile.existsById(id)) {
			throw new IllegalArgumentException("Add the weakness to the profile first.");
		}
		CoverageLanguage column = languageOf(language);
		GapDecision chosen = decisionOf(decision);
		CweGapDecisionEntity saved = decisions
				.save(new CweGapDecisionEntity(id, column, chosen, cleanNote(note), actor, clock.millis()));
		return view(saved);
	}

	@Transactional
	public void clearDecision(String cwe, String language) {
		int id = number(cwe).orElseThrow(() -> new IllegalArgumentException("Enter a CWE number, like CWE-79."));
		decisions.deleteById(CweGapDecisionEntity.key(id, languageOf(language)));
	}

	@Transactional(readOnly = true)
	public List<Decision> decisions() {
		return decisions.findAll().stream().sorted(Comparator.comparingInt(CweGapDecisionEntity::getCweId)
				.thenComparing(entity -> entity.getLanguage())).map(this::view).toList();
	}

	private CweProfileEntryEntity store(int id, CweProfilePriority level, String note, String actor) {
		Optional<CweProfileEntryEntity> existing = profile.findById(id);
		if (existing.isPresent()) {
			existing.get().update(level, note);
			return profile.save(existing.get());
		}
		if (profile.count() >= MAX_ENTRIES) {
			throw new IllegalArgumentException("The profile can hold at most " + MAX_ENTRIES + " weaknesses.");
		}
		return profile.save(new CweProfileEntryEntity(id, level, note, actor, clock.millis()));
	}

	/** Exists in the catalog when it is loaded; otherwise only the pinned Top 25 can be added. */
	private void requireKnown(int id) {
		if (catalog.isLoaded()) {
			if (catalog.find("CWE-" + id).isEmpty()) {
				throw new IllegalArgumentException("CWE-" + id + " is not in the CWE catalog.");
			}
		} else if (!top25.containsKey(id)) {
			throw new IllegalArgumentException("Load the CWE catalog on the Knowledge page to add other weaknesses.");
		}
	}

	private Entry view(CweProfileEntryEntity entity) {
		int id = entity.getCweId();
		Optional<CweEntry> found = catalog.isLoaded() ? catalog.find("CWE-" + id) : Optional.empty();
		String name = found.map(CweEntry::name).orElseGet(() -> Optional.ofNullable(top25.get(id)).map(RuleReviewReport.Entry::name).orElse(null));
		return new Entry(id, "CWE-" + id, name, entity.getPriority().name(), entity.getNote(), found.isPresent());
	}

	private Decision view(CweGapDecisionEntity entity) {
		return new Decision(entity.getCweId(), entity.getLanguage().name(), entity.getDecision().name(), entity.getNote(),
				entity.getDecidedBy(), entity.getDecidedAt());
	}

	static Optional<Integer> number(String cwe) {
		if (cwe == null) {
			return Optional.empty();
		}
		Matcher matcher = CWE.matcher(cwe.strip());
		return matcher.matches() ? Optional.of(Integer.parseInt(matcher.group(1))) : Optional.empty();
	}

	private static CweProfilePriority priorityOf(String priority) {
		try {
			return CweProfilePriority.valueOf(String.valueOf(priority).strip().toUpperCase(Locale.ROOT));
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("Priority must be critical, high or normal.");
		}
	}

	private static CoverageLanguage languageOf(String language) {
		try {
			return CoverageLanguage.valueOf(String.valueOf(language).strip().toUpperCase(Locale.ROOT));
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("Choose Java, Python, JavaScript or Other.");
		}
	}

	private static GapDecision decisionOf(String decision) {
		try {
			return GapDecision.valueOf(String.valueOf(decision).strip().toUpperCase(Locale.ROOT));
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("Choose not applicable, not coverable yet or defer.");
		}
	}

	/** Plain text, no control characters, at most {@link #MAX_NOTE} characters; blank becomes none. */
	private static String cleanNote(String note) {
		if (note == null) {
			return null;
		}
		String plain = note.codePoints().filter(cp -> !Character.isISOControl(cp))
				.collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append).toString().strip();
		if (plain.length() > MAX_NOTE) {
			throw new IllegalArgumentException("A note can have at most " + MAX_NOTE + " characters.");
		}
		return plain.isEmpty() ? null : plain;
	}
}
