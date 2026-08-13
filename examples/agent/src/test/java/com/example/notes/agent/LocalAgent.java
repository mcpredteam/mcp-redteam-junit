package com.example.notes.agent;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.ai.ollama.api.OllamaApi;
import org.springframework.ai.ollama.api.OllamaChatOptions;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * The Spring AI agent under test: a real model, running locally under Ollama.
 *
 * <p>This is the only file you would replace to point the example at your own stack. The harness
 * takes a plain {@link ChatClient}, so any Spring AI model provider works — swap the dependency
 * and the builder below.
 *
 * <p>Local rather than hosted for a reason beyond cost: measuring how often an agent is hijacked
 * means running the same task twenty or fifty times, and a per-token bill is exactly the pressure
 * that turns a rate measurement back into a single reassuring run.
 *
 * <p>Override with {@code -Dmcprt.model=...} and {@code -Dmcprt.ollama.url=...}. A hijack result
 * is a statement about one model, so changing this changes what the test found.
 */
final class LocalAgent {

    /**
     * A small tool-calling model, small on purpose. Weak instruction-following is what makes a
     * hijack observable, and a demo that needs a frontier model to show the attack landing is a
     * demo about that model rather than about the attack.
     */
    private static final String DEFAULT_MODEL = "qwen3:8b";
    private static final String DEFAULT_URL = "http://localhost:11434";

    private LocalAgent() {
    }

    static String model() {
        return System.getProperty("mcprt.model", DEFAULT_MODEL);
    }

    static String baseUrl() {
        return System.getProperty("mcprt.ollama.url", DEFAULT_URL);
    }

    /**
     * Builds the client, after checking the model is actually reachable.
     *
     * <p>The preflight is the point. Without it a stopped Ollama surfaces as a connection error
     * inside the tool-calling loop, the harness records a failed run, and the output reads as
     * though something about the agent went wrong. Failing here says plainly that nothing was
     * tested — which is the difference between a red build you can act on and one you learn to
     * re-run.
     */
    static ChatClient chatClient() {
        requireOllama();

        OllamaChatModel chatModel = OllamaChatModel.builder()
                .ollamaApi(OllamaApi.builder().baseUrl(baseUrl()).build())
                .build();

        // temperature 0 is the cheapest determinism available, and it is not much: Ollama still
        // samples, tool-call formatting still varies, and the same prompt can be obeyed on one
        // run and refused on the next. It narrows the spread. It does not make a hijack test a
        // gate — that is what measuring a rate is for.
        return ChatClient.builder(chatModel)
                .defaultOptions(OllamaChatOptions.builder()
                        .model(model())
                        .temperature(0.0))
                .build();
    }

    private static void requireOllama() {
        try (HttpClient http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(2))
                .build()) {

            HttpResponse<String> response = http.send(
                    HttpRequest.newBuilder(URI.create(baseUrl() + "/api/tags"))
                            .timeout(Duration.ofSeconds(5))
                            .GET()
                            .build(),
                    HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new IllegalStateException("Ollama at " + baseUrl() + " answered HTTP "
                        + response.statusCode());
            }
            if (!response.body().contains("\"" + model())) {
                throw new IllegalStateException("Ollama at " + baseUrl() + " is running but does not "
                        + "have '" + model() + "'. Pull it with: ollama pull " + model());
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while checking Ollama", e);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            // getMessage() is null on a plain ConnectException, the common case here, so fall
            // back to the type rather than printing "(null)".
            String cause = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
            throw new IllegalStateException("No Ollama at " + baseUrl() + " (" + cause
                    + "). Start it with: ollama serve", e);
        }
    }
}
