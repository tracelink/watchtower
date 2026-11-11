package com.tracelink.appsec.watchtower.core.cwe;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

import com.tracelink.appsec.watchtower.core.job.AsyncJobEntity;
import com.tracelink.appsec.watchtower.core.job.AsyncJobService;
import com.tracelink.appsec.watchtower.core.job.AsyncJobType;

/**
 * The CWE catalog as the rest of Watchtower uses it: look an entry up, check that a CWE exists and may be used,
 * find candidates for a rule by words, and ask for the catalog to be updated. Reads are served from a copy kept
 * in memory per pod, reloaded only when the stored release changes.
 */
@Service
public class CweCatalogService {
	/** How a CWE is written: {@code CWE-79} in any case, or just the number. */
	private static final Pattern LABEL = Pattern.compile("(?i)(?:CWE-)?([1-9][0-9]{0,8})");
	private static final Pattern CAMEL = Pattern.compile("(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])");
	private static final Pattern NOT_WORD = Pattern.compile("[^a-z0-9]+");
	private static final Set<String> STOP = Set.of("the", "and", "for", "with", "rule", "check", "avoid", "use", "using", "not",
			"from", "that", "this", "are", "can", "should", "must", "unused", "when", "into", "bad", "may", "any", "all");
	/** Short names people use in rule names and messages, expanded to the words MITRE uses. */
	private static final Map<String, String> ABBREVIATIONS = Map.ofEntries(Map.entry("xss", "cross site scripting"),
			Map.entry("csrf", "cross site request forgery"), Map.entry("ssrf", "server side request forgery"),
			Map.entry("xxe", "xml external entity"), Map.entry("sqli", "sql injection"),
			Map.entry("rce", "command code injection"), Map.entry("idor", "authorization user controlled key"),
			Map.entry("redos", "regular expression complexity"), Map.entry("crypto", "cryptographic"),
			Map.entry("hardcoded", "hard coded"), Map.entry("ldap", "ldap injection"));
	private static final int NAME_WORD = 3, DESCRIPTION_WORD = 1;
	private static final String JOB_KEY = "cwe-catalog";

	/**
	 * @param state    NEVER, OK, FAILED or UPDATING
	 * @param version  the stored release, or null
	 * @param date     the stored release date, or null
	 * @param count    how many weaknesses are stored
	 * @param message  the last error, or null
	 * @param progress what the running update is doing, or null
	 * @param fetchedAt when the stored release was loaded, or null
	 * @param by       who loaded it, or null
	 */
	public record Status(String state, String version, String date, int count, String message, String progress, Long fetchedAt,
			String by) {
	}

	private record Snapshot(Long fetchedAt, Map<Integer, CweEntry> byId, Map<Integer, Set<String>> nameWords,
			Map<Integer, Set<String>> descriptionWords) {
	}

	private final CweCatalogStore store;
	private final ObjectProvider<AsyncJobService> jobs;
	private volatile Snapshot snapshot;

	public CweCatalogService(CweCatalogStore store, ObjectProvider<AsyncJobService> jobs) {
		this.store = store;
		this.jobs = jobs;
	}

	/** @return where the catalog stands, for the Knowledge page chip */
	public Status status() {
		CweCatalogMetaEntity meta = store.meta();
		Optional<AsyncJobEntity> running = jobs.getObject().getActiveJobs().stream()
				.filter(job -> job.getType() == AsyncJobType.CWE_CATALOG_REFRESH).findFirst();
		String state = running.isPresent() ? "UPDATING" : meta.getRefreshStatus();
		String progress = running.map(AsyncJobEntity::getProgress).filter(text -> text != null && !text.isBlank()).orElse(null);
		return new Status(state, meta.getContentVersion(), meta.getReleaseDate(), meta.getEntryCount(), meta.getLastError(),
				progress, meta.getFetchedAt(), meta.getRefreshedBy());
	}

	/**
	 * Queues an update unless one is already waiting or running.
	 *
	 * @return whether a new update was queued
	 */
	public boolean requestRefresh(String actor, boolean force) {
		return jobs.getObject()
				.enqueue(AsyncJobType.CWE_CATALOG_REFRESH, force ? CweCatalogJob.FORCE : "", JOB_KEY, actor).isPresent();
	}

	public boolean isLoaded() {
		return !snapshot().byId().isEmpty();
	}

	/** @param cwe {@code CWE-79}, {@code cwe-79} or {@code 79} */
	public Optional<CweEntry> find(String cwe) {
		return number(cwe).map(snapshot().byId()::get);
	}

	/** @return whether the CWE exists in the catalog and MITRE has not discouraged mapping to it */
	public boolean isUsable(String cwe) {
		return find(cwe).filter(CweEntry::isMappable).isPresent();
	}

	/** @return {@code CWE-79 · Improper Neutralization...}, or null if the CWE is not in the catalog */
	public String name(String cwe) {
		return find(cwe).map(entry -> entry.label() + " · " + entry.name()).orElse(null);
	}

	/**
	 * The hover text of a CWE chip: the weakness name (or why there is none) and what the CWE is for. Built here
	 * because a template that concatenates and branches on beans trips Thymeleaf's restricted expressions.
	 */
	public String chipTip(String cwe, String role) {
		String what = !isLoaded() ? "The CWE catalog is not loaded" : find(cwe).map(entry -> entry.label() + " · " + entry.name())
				.orElse("Not in the loaded CWE catalog");
		return what + "\n" + role;
	}

	/**
	 * One CWE chip on a rule page.
	 *
	 * @param label   {@code CWE-89}
	 * @param tip     the hover text: the weakness name and what the CWE is for
	 * @param warn    whether the chip is amber because the loaded catalog does not allow the CWE
	 * @param primary whether it is the rule's primary CWE
	 */
	public record ChipView(String label, String tip, boolean warn, boolean primary) {
	}

	/** The chips for a rule's CWEs, primary first. Pages receive these ready-made, never the catalog itself. */
	public List<ChipView> chipsFor(String primary, String secondaryList) {
		List<ChipView> chips = new java.util.ArrayList<>();
		if (primary != null && !primary.isBlank()) {
			chips.add(new ChipView(primary.strip(), chipTip(primary, "Primary: used for coverage and reports"),
					needsAttention(primary), true));
		}
		for (String secondary : split(secondaryList)) {
			chips.add(new ChipView(secondary, chipTip(secondary, "Secondary"), needsAttention(secondary), false));
		}
		return chips;
	}

	/** @return whether a chip should be amber: there is a catalog to check against and it does not allow this CWE */
	public boolean needsAttention(String cwe) {
		return isLoaded() && !isUsable(cwe);
	}

	/** {@code "CWE-1, ,CWE-2"} becomes {@code [CWE-1, CWE-2]}; null and blank become an empty list. */
	public static List<String> split(String list) {
		if (list == null || list.isBlank()) {
			return List.of();
		}
		return java.util.Arrays.stream(list.split(",")).map(String::strip).filter(part -> !part.isEmpty()).toList();
	}

	/** Entries that may be used for a new mapping and best fit the words in {@code text}. */
	public List<CweEntry> shortlist(String text, int limit) {
		return rank(text, limit, CweEntry::isMappable);
	}

	/** A number looks one entry up; words search every non-deprecated entry, discouraged ones included. */
	public List<CweEntry> search(String query, int limit) {
		Optional<Integer> id = number(query == null ? null : query.strip());
		if (id.isPresent()) {
			return Optional.ofNullable(snapshot().byId().get(id.get())).map(List::of).orElse(List.of());
		}
		return rank(query, limit, entry -> true);
	}

	private List<CweEntry> rank(String text, int limit, Predicate<CweEntry> allowed) {
		Snapshot current = snapshot();
		Set<String> wanted = words(text);
		if (wanted.isEmpty() || limit < 1) {
			return List.of();
		}
		record Scored(CweEntry entry, int score) {
		}
		List<Scored> scored = new ArrayList<>();
		for (CweEntry entry : current.byId().values()) {
			if (!allowed.test(entry) || "Deprecated".equalsIgnoreCase(entry.status())) {
				continue;
			}
			int score = 0;
			for (String word : wanted) {
				if (current.nameWords().get(entry.id()).contains(word)) {
					score += NAME_WORD;
				} else if (current.descriptionWords().get(entry.id()).contains(word)) {
					score += DESCRIPTION_WORD;
				}
			}
			if (score > 0) {
				scored.add(new Scored(entry, score + abstractionBonus(entry)));
			}
		}
		return scored.stream().sorted(Comparator.comparingInt(Scored::score).reversed().thenComparingInt(s -> s.entry().id()))
				.limit(limit).map(Scored::entry).toList();
	}

	private static int abstractionBonus(CweEntry entry) {
		String abstraction = entry.abstraction() == null ? "" : entry.abstraction();
		return switch (abstraction) {
			case "Base", "Variant" -> 1;
			case "Pillar" -> -1;
			default -> 0;
		};
	}

	private static Optional<Integer> number(String cwe) {
		if (cwe == null) {
			return Optional.empty();
		}
		Matcher matcher = LABEL.matcher(cwe.strip());
		return matcher.matches() ? Optional.of(Integer.parseInt(matcher.group(1))) : Optional.empty();
	}

	/** Lower-case word stems from free text or a CamelCase rule name, with common abbreviations spelled out. */
	static Set<String> words(String text) {
		if (text == null) {
			return Set.of();
		}
		String spaced = CAMEL.matcher(text).replaceAll(" ").toLowerCase(Locale.ROOT);
		Set<String> found = new LinkedHashSet<>();
		for (String raw : NOT_WORD.split(spaced)) {
			String expansion = ABBREVIATIONS.get(raw);
			for (String word : expansion == null ? new String[] { raw } : expansion.split(" ")) {
				if (word.length() >= 3 && !STOP.contains(word)) {
					found.add(stem(word));
				}
			}
		}
		return found;
	}

	private static String stem(String word) {
		for (String suffix : new String[] { "ing", "ed", "es", "s" }) {
			if (word.endsWith(suffix) && word.length() - suffix.length() >= 4) {
				return word.substring(0, word.length() - suffix.length());
			}
		}
		return word;
	}

	private Snapshot snapshot() {
		CweCatalogMetaEntity meta = store.meta();
		Snapshot current = snapshot;
		if (current != null && Objects.equals(current.fetchedAt(), meta.getFetchedAt())) {
			return current;
		}
		synchronized (this) {
			if (snapshot != null && Objects.equals(snapshot.fetchedAt(), meta.getFetchedAt())) {
				return snapshot;
			}
			Map<Integer, CweEntry> byId = new java.util.LinkedHashMap<>();
			Map<Integer, Set<String>> names = new java.util.HashMap<>();
			Map<Integer, Set<String>> descriptions = new java.util.HashMap<>();
			if (meta.getFetchedAt() != null) {
				for (CweEntry entry : store.all()) {
					byId.put(entry.id(), entry);
					names.put(entry.id(), words(entry.name()));
					Set<String> described = new HashSet<>(words(entry.description()));
					descriptions.put(entry.id(), described);
				}
			}
			snapshot = new Snapshot(meta.getFetchedAt(), byId, names, descriptions);
			return snapshot;
		}
	}
}
