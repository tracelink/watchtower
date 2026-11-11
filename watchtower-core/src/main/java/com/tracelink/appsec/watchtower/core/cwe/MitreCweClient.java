package com.tracelink.appsec.watchtower.core.cwe;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

/**
 * Reads the CWE catalog from MITRE's public REST API. The host is fixed in code (nothing configurable, so
 * nothing to point at an internal address), redirects are never followed, requests are paced and bounded,
 * and every answer is size-capped and parsed with limits. Nothing about Watchtower, its customers or their
 * code is sent: only catalog numbers.
 */
@Component
public class MitreCweClient implements CweCatalogClient {

	static final String BASE = "https://cwe-api.mitre.org/api/v1";
	private static final String RESEARCH_VIEW = "1000";
	private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(5);
	private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
	private static final int MAX_DESCRIPTION = 2000, MAX_NAME = 255, MAX_FIELD = 16, MAX_USAGE = 32;
	private static final int MAX_TREE_DEPTH = 32, MAX_IDS = 5000, MAX_PARENTS = 20;
	private static final Pattern VERSION = Pattern.compile("[0-9]{1,3}\\.[0-9]{1,3}(\\.[0-9]{1,3})?");
	private static final Pattern DATE = Pattern.compile("[0-9]{4}-[0-9]{2}-[0-9]{2}");
	private static final Pattern MARKUP = Pattern.compile("<[^>]{0,200}>");
	private static final ObjectMapper MAPPER = JsonMapper.builder(JsonFactory.builder()
			.streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(64).maxStringLength(200_000).build()).build())
			.build();

	/**
	 * @param pauseMillis      wait before every request, so the API is not hammered (MITRE publishes no limit)
	 * @param maxResponseBytes the largest answer that is read
	 * @param attempts         how many times one request is tried when the API is busy or unreachable
	 * @param backoffMillis    the first wait between attempts; it doubles each time
	 */
	public record Limits(long pauseMillis, int maxResponseBytes, int attempts, long backoffMillis) {
		static final Limits DEFAULT = new Limits(500, 5 * 1024 * 1024, 3, 2000);
	}

	/** Waits; replaced in tests. */
	@FunctionalInterface
	interface Pause {
		void pause(long millis) throws InterruptedException;
	}

	private final HttpClient client;
	private final URI base;
	private final Limits limits;
	private final Pause pause;

	public MitreCweClient() {
		this(HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).followRedirects(HttpClient.Redirect.NEVER).build(),
				URI.create(BASE), Limits.DEFAULT, Thread::sleep);
	}

	MitreCweClient(HttpClient client, URI base, Limits limits, Pause pause) {
		this.client = client;
		this.base = base;
		this.limits = limits;
		this.pause = pause;
	}

	@Override
	public Version version() throws IOException {
		JsonNode node = get("/cwe/version");
		String version = node.path("ContentVersion").asText("");
		String date = node.path("ContentDate").asText("");
		int weaknesses = node.path("TotalWeaknesses").asInt(-1);
		if (!VERSION.matcher(version).matches() || !DATE.matcher(date).matches() || weaknesses < 1) {
			throw new IOException("MITRE sent an unexpected version answer");
		}
		return new Version(version, date, weaknesses);
	}

	@Override
	public List<Integer> topLevelIds() throws IOException {
		List<Integer> ids = new ArrayList<>();
		for (JsonNode member : get("/cwe/view/" + RESEARCH_VIEW).path("Views").path(0).path("Members")) {
			number(member.path("CweID")).ifPresent(ids::add);
		}
		if (ids.isEmpty() || ids.size() > MAX_IDS) {
			throw new IOException("MITRE sent an unexpected view answer");
		}
		return ids;
	}

	@Override
	public Set<Integer> descendantIds(int id) throws IOException {
		requireCweNumber(id);
		Set<Integer> found = new LinkedHashSet<>();
		JsonNode roots = get("/cwe/" + id + "/descendants?view=" + RESEARCH_VIEW);
		if (!roots.isArray()) {
			throw new IOException("MITRE sent an unexpected descendants answer");
		}
		for (JsonNode root : roots) {
			collect(root.path("Children"), found, 1);
		}
		return found;
	}

	@Override
	public List<CweEntry> weaknesses(List<Integer> ids) throws IOException {
		ids.forEach(MitreCweClient::requireCweNumber);
		if (ids.isEmpty()) {
			return List.of();
		}
		JsonNode weaknesses = get("/cwe/weakness/" + String.join(",", ids.stream().map(String::valueOf).toList()))
				.path("Weaknesses");
		if (!weaknesses.isArray()) {
			throw new IOException("MITRE sent an unexpected weakness answer");
		}
		List<CweEntry> entries = new ArrayList<>();
		for (JsonNode weakness : weaknesses) {
			entry(weakness).ifPresent(entries::add);
		}
		return entries;
	}

	private static void requireCweNumber(int id) {
		if (id < 1) {
			throw new IllegalArgumentException("Not a CWE number: " + id);
		}
	}

	private static void collect(JsonNode children, Set<Integer> found, int depth) throws IOException {
		if (!children.isArray()) {
			return;
		}
		if (depth > MAX_TREE_DEPTH || found.size() > MAX_IDS) {
			throw new IOException("MITRE sent an unexpectedly deep descendants answer");
		}
		for (JsonNode child : children) {
			number(child.path("Data").path("ID")).ifPresent(found::add);
			collect(child.path("Children"), found, depth + 1);
		}
	}

	private static java.util.Optional<CweEntry> entry(JsonNode weakness) {
		var id = number(weakness.path("ID"));
		String name = clean(weakness.path("Name").asText(null), MAX_NAME);
		if (id.isEmpty() || name == null || name.isEmpty()) {
			return java.util.Optional.empty();
		}
		List<Integer> parents = new ArrayList<>();
		for (JsonNode related : weakness.path("RelatedWeaknesses")) {
			if ("ChildOf".equals(related.path("Nature").asText()) && RESEARCH_VIEW.equals(related.path("ViewID").asText())
					&& parents.size() < MAX_PARENTS) {
				number(related.path("CweID")).ifPresent(parents::add);
			}
		}
		String usage = clean(weakness.path("MappingNotes").path("Usage").asText(null), MAX_USAGE);
		return java.util.Optional.of(new CweEntry(id.get(), name, clean(weakness.path("Abstraction").asText(null), MAX_FIELD),
				clean(weakness.path("Structure").asText(null), MAX_FIELD), clean(weakness.path("Status").asText(null), MAX_FIELD),
				usage == null || usage.isEmpty() ? "Unknown" : usage,
				clean(weakness.path("Description").asText(null), MAX_DESCRIPTION),
				clean(weakness.path("LikelihoodOfExploit").asText(null), MAX_FIELD), parents));
	}

	private static java.util.Optional<Integer> number(JsonNode node) {
		try {
			int value = Integer.parseInt(node.asText(""));
			return value > 0 ? java.util.Optional.of(value) : java.util.Optional.empty();
		} catch (NumberFormatException e) {
			return java.util.Optional.empty();
		}
	}

	/** Plain text only: no markup, no control characters, bounded length. */
	static String clean(String text, int max) {
		if (text == null) {
			return null;
		}
		String plain = MARKUP.matcher(text).replaceAll("");
		StringBuilder out = new StringBuilder(plain.length());
		plain.codePoints().forEach(cp -> {
			if (!Character.isISOControl(cp)) {
				out.appendCodePoint(cp);
			}
		});
		String stripped = out.toString().strip();
		return stripped.length() > max ? stripped.substring(0, max).strip() : stripped;
	}

	private JsonNode get(String pathAndQuery) throws IOException {
		HttpRequest request = HttpRequest.newBuilder(URI.create(base + pathAndQuery)).timeout(REQUEST_TIMEOUT)
				.header("Accept", "application/json").GET().build();
		String last = "no answer";
		for (int attempt = 1; attempt <= limits.attempts(); attempt++) {
			sleep(limits.pauseMillis());
			try {
				HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
				int code = response.statusCode();
				if (code == 200) {
					return parse(read(response.body()));
				}
				if (code != 429 && code < 500) {
					throw new IOException("MITRE answered HTTP " + code);
				}
				last = "HTTP " + code;
			} catch (IOException e) {
				if (e.getMessage() != null && (e.getMessage().startsWith("MITRE") || e.getMessage().contains("too large"))) {
					throw e;
				}
				last = "connection failed (" + e.getClass().getSimpleName() + ")";
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new IOException("The update was interrupted");
			}
			if (attempt < limits.attempts()) {
				sleep(limits.backoffMillis() << (attempt - 1));
			}
		}
		throw new IOException("MITRE did not answer after " + limits.attempts() + " tries (" + last + ")");
	}

	private void sleep(long millis) throws IOException {
		try {
			pause.pause(millis);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IOException("The update was interrupted");
		}
	}

	private byte[] read(InputStream body) throws IOException {
		try (body) {
			ByteArrayOutputStream bytes = new ByteArrayOutputStream();
			byte[] buffer = new byte[8192];
			int read;
			while ((read = body.read(buffer)) != -1) {
				bytes.write(buffer, 0, read);
				if (bytes.size() > limits.maxResponseBytes()) {
					throw new IOException("MITRE sent an answer that is too large");
				}
			}
			return bytes.toByteArray();
		}
	}

	private static JsonNode parse(byte[] bytes) throws IOException {
		try {
			JsonNode node = MAPPER.readTree(new String(bytes, StandardCharsets.UTF_8));
			if (node == null || !(node.isObject() || node.isArray())) {
				throw new IOException("MITRE sent an unexpected answer");
			}
			return node;
		} catch (JsonProcessingException e) {
			throw new IOException("MITRE sent an unexpected answer");
		}
	}
}
