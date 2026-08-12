package io.github.mcpredteam.core.fixture;

import io.github.mcpredteam.core.ToolDefinition;

import java.util.List;
import java.util.Map;

/**
 * Honest tool definitions that must produce no high-severity findings.
 *
 * <p>This corpus is deliberately adversarial <em>towards the scanner</em>. Several entries
 * contain the exact words a lazy rule would key on — "base64", "system prompt", "delete",
 * "credentials", "webhook" — in their ordinary, legitimate sense. A rule set that flags
 * these is worse than useless: teams mute a scanner that cries wolf, and then it is not
 * there when a real poisoned tool arrives.
 *
 * <p>Treat a new false positive here as a build failure, not a tuning detail.
 */
public final class BenignToolFixtures {

    private BenignToolFixtures() {
    }

    private static final String SERVER = "acme-tools";

    /** Says "base64" repeatedly, in the normal sense. */
    public static ToolDefinition imageTool() {
        return ToolDefinition.of(SERVER, "get_thumbnail",
                "Returns a base64-encoded PNG thumbnail for the given asset. The base64 payload is "
                        + "suitable for embedding directly in an img tag as a data URI.",
                Map.of("type", "object",
                        "properties", Map.of(
                                "assetId", Map.of("type", "string", "description", "Asset identifier"),
                                "width", Map.of("type", "integer", "description", "Width in pixels"))));
    }

    /** Mentions "system prompt" descriptively, with no directive to send it anywhere. */
    public static ToolDefinition promptLibraryTool() {
        return ToolDefinition.of(SERVER, "list_prompts",
                "Lists the prompt templates stored in the workspace, including each template's "
                        + "system prompt and description, so an operator can review them.",
                Map.of("type", "object",
                        "properties", Map.of(
                                "folder", Map.of("type", "string", "description", "Folder to list"))));
    }

    /** Destructive, but honestly annotated, so it should not be flagged. */
    public static ToolDefinition annotatedDeleteTool() {
        return new ToolDefinition(SERVER, "delete_document", "Delete document",
                "Permanently deletes a document from the workspace.",
                Map.of("type", "object",
                        "properties", Map.of("documentId", Map.of("type", "string", "description", "Document id"))),
                Map.of(),
                Map.of("destructiveHint", true, "readOnlyHint", false));
    }

    /** Legitimately handles credentials, without telling the agent to read or forward them. */
    public static ToolDefinition credentialVaultTool() {
        return ToolDefinition.of(SERVER, "rotate_api_key",
                "Rotates the API key for a service account. The new credentials are returned to the "
                        + "caller and are never written to logs.",
                Map.of("type", "object",
                        "properties", Map.of(
                                "accountId", Map.of("type", "string", "description", "Service account id"))));
    }

    /** A real webhook integration: the parameter name is a sink, which is expected here. */
    public static ToolDefinition webhookTool() {
        return ToolDefinition.of(SERVER, "register_webhook",
                "Registers a webhook subscription so the workspace can notify an external system "
                        + "when a document changes.",
                Map.of("type", "object",
                        "properties", Map.of(
                                "callback_url", Map.of("type", "string", "description", "HTTPS endpoint to notify"),
                                "events", Map.of("type", "array", "description", "Event names to subscribe to"))));
    }

    /** Ordinary documentation prose with imperative-sounding but descriptive language. */
    public static ToolDefinition searchTool() {
        return ToolDefinition.of(SERVER, "search_documents",
                "Full-text search across the workspace. Results are ranked by relevance. "
                        + "Before calling this tool, ensure the workspace has finished indexing, "
                        + "otherwise recent documents may be missing.",
                Map.of("type", "object",
                        "properties", Map.of(
                                "query", Map.of("type", "string", "description", "Search query"),
                                "limit", Map.of("type", "integer", "description", "Maximum results", "default", 20))));
    }

    public static List<ToolDefinition> all() {
        return List.of(
                imageTool(),
                promptLibraryTool(),
                annotatedDeleteTool(),
                credentialVaultTool(),
                webhookTool(),
                searchTool());
    }
}
