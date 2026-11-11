package com.tracelink.appsec.watchtower.core.cwe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/** The MITRE client against a local fake of the API: shapes, retries, size and redirect limits. */
class MitreCweClientTest {
	private static final String WEAKNESS_79 = "{\"ID\":\"79\",\"Name\":\"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')\","
			+ "\"Abstraction\":\"Base\",\"Structure\":\"Simple\",\"Status\":\"Stable\",\"LikelihoodOfExploit\":\"High\","
			+ "\"Description\":\"The product does <xhtml:b>not</xhtml:b> neutralize\\u0007 input.\","
			+ "\"RelatedWeaknesses\":[{\"Nature\":\"ChildOf\",\"CweID\":\"74\",\"ViewID\":\"1000\"},{\"Nature\":\"ChildOf\",\"CweID\":\"74\",\"ViewID\":\"1003\"},"
			+ "{\"Nature\":\"PeerOf\",\"CweID\":\"352\",\"ViewID\":\"1000\"},{\"Nature\":\"ChildOf\",\"CweID\":\"x\",\"ViewID\":\"1000\"}],"
			+ "\"MappingNotes\":{\"Usage\":\"Allowed\"},\"Examples\":\"ignored\"}";
	private static final String WEAKNESS_74 = "{\"ID\":\"74\",\"Name\":\"Injection\",\"Abstraction\":\"Class\",\"Status\":\"Draft\","
			+ "\"Description\":\"Injection.\",\"MappingNotes\":{\"Usage\":\"Discouraged\"}}";

	private HttpServer server;
	private Function<HttpExchange, byte[]> handler;
	private final List<Long> pauses = new ArrayList<>();
	private final AtomicInteger requests = new AtomicInteger();
	private int status = 200;

	@BeforeEach
	void start() throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/api/v1/cwe", exchange -> {
			requests.incrementAndGet();
			byte[] body = handler.apply(exchange);
			exchange.getResponseHeaders().add("Content-Type", "application/json");
			exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
			if (body.length > 0) {
				exchange.getResponseBody().write(body);
			}
			exchange.close();
		});
		server.start();
	}

	@AfterEach
	void stop() {
		server.stop(0);
	}

	private MitreCweClient client(MitreCweClient.Limits limits) {
		URI base = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/api/v1");
		return new MitreCweClient(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(), base, limits,
				pauses::add);
	}

	private MitreCweClient client() {
		return client(new MitreCweClient.Limits(500, 1_000_000, 3, 2000));
	}

	private static byte[] json(String text) {
		return text.getBytes(StandardCharsets.UTF_8);
	}

	@Test
	void readsTheVersionAndPausesBeforeEveryRequest() throws IOException {
		handler = x -> json("{\"ContentVersion\":\"4.20\",\"ContentDate\":\"2026-04-30\",\"TotalWeaknesses\":969,\"TotalCategories\":422}");

		var version = client().version();

		assertThat(version).isEqualTo(new CweCatalogClient.Version("4.20", "2026-04-30", 969));
		assertThat(pauses).containsExactly(500L);
	}

	@Test
	void rejectsAVersionThatIsNotANumber() {
		handler = x -> json("{\"ContentVersion\":\"<script>\",\"ContentDate\":\"2026-04-30\",\"TotalWeaknesses\":969}");

		assertThatThrownBy(() -> client().version()).isInstanceOf(IOException.class);
	}

	@Test
	void listsTheTopLevelEntriesOfTheResearchConceptsView() throws IOException {
		handler = x -> {
			assertThat(x.getRequestURI().getPath()).isEqualTo("/api/v1/cwe/view/1000");
			return json("{\"Views\":[{\"ID\":\"1000\",\"Members\":[{\"CweID\":\"284\",\"ViewID\":\"1000\"},{\"CweID\":\"664\"}]}]}");
		};

		assertThat(client().topLevelIds()).containsExactly(284, 664);
	}

	@Test
	void collectsEveryDescendantButNotTheEntryItself() throws IOException {
		handler = x -> {
			assertThat(x.getRequestURI().toString()).isEqualTo("/api/v1/cwe/664/descendants?view=1000");
			return json("[{\"Data\":{\"Type\":\"pillar_weakness\",\"ID\":\"664\"},\"Children\":[{\"Data\":{\"ID\":\"665\"},"
					+ "\"Children\":[{\"Data\":{\"ID\":\"666\"},\"Children\":null}]},{\"Data\":{\"ID\":\"667\"},\"Children\":null}]}]");
		};

		assertThat(client().descendantIds(664)).containsExactlyInAnyOrder(665, 666, 667);
	}

	@Test
	void keepsOnlyWhatWatchtowerUsesAndCleansTheText() throws IOException {
		handler = x -> {
			assertThat(x.getRequestURI().getPath()).isEqualTo("/api/v1/cwe/weakness/79,74");
			return json("{\"Weaknesses\":[" + WEAKNESS_79 + "," + WEAKNESS_74 + "]}");
		};

		var entries = client().weaknesses(List.of(79, 74));

		assertThat(entries).hasSize(2);
		var xss = entries.get(0);
		assertThat(xss.id()).isEqualTo(79);
		assertThat(xss.name()).contains("Cross-site Scripting");
		assertThat(xss.abstraction()).isEqualTo("Base");
		assertThat(xss.usage()).isEqualTo("Allowed");
		assertThat(xss.likelihood()).isEqualTo("High");
		assertThat(xss.parents()).containsExactly(74);
		assertThat(xss.description()).isEqualTo("The product does not neutralize input.");
		assertThat(entries.get(1).usage()).isEqualTo("Discouraged");
		assertThat(entries.get(1).isMappable()).isFalse();
		assertThat(entries.get(1).parents()).isEmpty();
	}

	@Test
	void capsAVeryLongDescription() throws IOException {
		handler = x -> json("{\"Weaknesses\":[{\"ID\":\"1\",\"Name\":\"N\",\"Description\":\"" + "a".repeat(5000)
				+ "\",\"MappingNotes\":{\"Usage\":\"Allowed\"}}]}");

		assertThat(client().weaknesses(List.of(1)).get(0).description()).hasSize(2000);
	}

	@Test
	void refusesNumbersThatAreNotCweNumbersBeforeAskingAnything() {
		assertThatThrownBy(() -> client().weaknesses(List.of(79, -1))).isInstanceOf(IllegalArgumentException.class);
		assertThat(requests.get()).isZero();
	}

	@Test
	void retriesAnUnavailableServerWithGrowingPauses() throws IOException {
		var calls = new AtomicInteger();
		handler = x -> {
			if (calls.incrementAndGet() < 3) {
				status = 503;
				return new byte[0];
			}
			status = 200;
			return json("{\"ContentVersion\":\"4.20\",\"ContentDate\":\"2026-04-30\",\"TotalWeaknesses\":969}");
		};

		assertThat(client().version().version()).isEqualTo("4.20");
		assertThat(requests.get()).isEqualTo(3);
		assertThat(pauses).containsExactly(500L, 2000L, 500L, 4000L, 500L);
	}

	@Test
	void givesUpAfterTheAttemptsWithAMessageThatIsSafeToShow() {
		handler = x -> {
			status = 429;
			return new byte[0];
		};

		assertThatThrownBy(() -> client().version()).isInstanceOf(IOException.class)
				.hasMessageContaining("429").hasMessageNotContaining("127.0.0.1");
		assertThat(requests.get()).isEqualTo(3);
	}

	@Test
	void doesNotRetryAnAnswerThatWillNotChange() {
		handler = x -> {
			status = 404;
			return new byte[0];
		};

		assertThatThrownBy(() -> client().version()).isInstanceOf(IOException.class).hasMessageContaining("404");
		assertThat(requests.get()).isEqualTo(1);
	}

	@Test
	void doesNotFollowARedirect() {
		handler = x -> {
			status = 302;
			x.getResponseHeaders().add("Location", "http://169.254.169.254/latest/meta-data");
			return new byte[0];
		};

		assertThatThrownBy(() -> client().version()).isInstanceOf(IOException.class).hasMessageContaining("302");
		assertThat(requests.get()).isEqualTo(1);
	}

	@Test
	void refusesAnAnswerLargerThanTheLimit() {
		handler = x -> json("{\"pad\":\"" + "x".repeat(2000) + "\"}");

		assertThatThrownBy(() -> client(new MitreCweClient.Limits(0, 1000, 1, 0)).version())
				.isInstanceOf(IOException.class).hasMessageContaining("too large");
	}

	@Test
	void refusesAnAnswerThatIsNotTheExpectedJson() {
		handler = x -> json("<html>maintenance</html>");

		assertThatThrownBy(() -> client().version()).isInstanceOf(IOException.class).hasMessageContaining("unexpected");
	}
}
