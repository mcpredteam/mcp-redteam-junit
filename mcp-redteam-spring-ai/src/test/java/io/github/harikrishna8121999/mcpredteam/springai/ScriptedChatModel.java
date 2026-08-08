package io.github.harikrishna8121999.mcpredteam.springai;

import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.model.Generation;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.model.tool.ToolCallingChatOptions;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A chat model that replays a fixed script instead of calling a provider.
 *
 * <p>It exists so the harness itself can be tested. Whether a given LLM resists a poisoned tool
 * is a question about that model; whether the harness <em>notices</em> when an agent is hijacked
 * is a question about this code, and only the second one belongs in CI. Scripting the model
 * makes the second question deterministic, free, and answerable with no API key.
 *
 * <p>This is not a claim that any real agent behaves this way. The scripted agent is made to
 * misbehave on purpose, so that a harness which quietly failed to record the misbehaviour would
 * turn the suite red.
 */
final class ScriptedChatModel implements ChatModel {

    private final List<ChatResponse> script;
    private final RuntimeException failure;
    private final AtomicInteger turn = new AtomicInteger();

    private ScriptedChatModel(List<ChatResponse> script, RuntimeException failure) {
        this.script = List.copyOf(script);
        this.failure = failure;
    }

    /** Requests the named tools in one turn, then answers with {@code finalAnswer}. */
    static ScriptedChatModel callingTools(String finalAnswer, ToolRequest... requests) {
        List<AssistantMessage.ToolCall> calls = new ArrayList<>();
        for (int i = 0; i < requests.length; i++) {
            calls.add(new AssistantMessage.ToolCall("call-" + i, "function",
                    requests[i].name(), requests[i].arguments()));
        }
        return new ScriptedChatModel(List.of(
                response(AssistantMessage.builder().content("").toolCalls(calls).build()),
                response(new AssistantMessage(finalAnswer))), null);
    }

    /** Answers directly without touching a tool. */
    static ScriptedChatModel answering(String finalAnswer) {
        return new ScriptedChatModel(List.of(response(new AssistantMessage(finalAnswer))), null);
    }

    /** Stands in for a provider outage or rate limit. */
    static ScriptedChatModel failingWith(RuntimeException error) {
        return new ScriptedChatModel(List.of(), error);
    }

    @Override
    public ChatResponse call(Prompt prompt) {
        if (failure != null) {
            throw failure;
        }
        int index = turn.getAndIncrement();
        if (index >= script.size()) {
            throw new IllegalStateException(
                    "The scripted model ran out of turns at " + (index + 1) + ". The tool-calling loop "
                            + "iterated more times than the script expects.");
        }
        return script.get(index);
    }

    /**
     * Spring AI builds the prompt's options from {@code getOptions()} and engages the
     * tool-calling loop only when the result is a {@code ToolCallingChatOptions}. Real provider
     * models return one; a stub that does not gets no tool execution at all, which is
     * indistinguishable from an agent that simply behaved itself.
     */
    @Override
    public ChatOptions getOptions() {
        return ToolCallingChatOptions.builder().build();
    }

    private static ChatResponse response(AssistantMessage message) {
        return new ChatResponse(List.of(new Generation(message)));
    }

    /** One scripted tool request. Arguments are raw JSON, exactly as a model would emit them. */
    record ToolRequest(String name, String arguments) {
        static ToolRequest of(String name, String arguments) {
            return new ToolRequest(name, arguments);
        }
    }

}
