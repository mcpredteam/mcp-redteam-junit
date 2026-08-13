# Choosing your modules

Four modules are published. Which you need depends on one question: **what do you have in hand?**

| You have | You need | Extra dependencies you supply |
| --- | --- | --- |
| Tool definitions already (from your MCP client, or written by hand) | `mcp-redteam-junit` | JUnit engine |
| A server URL or command, and want the scan to fetch `tools/list` | `+ mcp-redteam-mcp` | MCP SDK |
| A Spring AI agent, and want to test whether a model can be hijacked | `+ mcp-redteam-spring-ai` | Spring AI, MCP SDK |

`mcp-redteam-core` comes in transitively and is never declared directly. It has **zero
dependencies**, which is the property that lets the scanner run anywhere.

## The `provided` scope trap

Read this once and you will save yourself a confusing hour.

`mcp-redteam-mcp` declares the MCP SDK as `provided`. `mcp-redteam-spring-ai` declares Spring AI,
`spring-ai-mcp`, Jackson and the MCP SDK the same way. This is deliberate: a *test* library that
drags its own Spring AI version onto your classpath and silently overrides the one you pinned is a
worse problem than the one it solves.

**`provided` dependencies are not transitive.** Maven and Gradle will resolve your build happily
without them. You find out at test time:

```
java.lang.NoClassDefFoundError: io/modelcontextprotocol/client/McpSyncClient
```

That is the bill. Both example poms mark the affected lines with comments.

## Maven

### Scanning only — no model, no agent

Four dependencies. This is what most teams keep in CI.

```xml
<properties>
    <mcp-redteam.version>0.1.0</mcp-redteam.version>
    <mcp-sdk.version>2.0.0</mcp-sdk.version>
    <junit.version>5.11.4</junit.version>
</properties>

<dependencies>
    <dependency>
        <groupId>io.github.mcpredteam</groupId>
        <artifactId>mcp-redteam-junit</artifactId>
        <version>${mcp-redteam.version}</version>
        <scope>test</scope>
    </dependency>

    <!-- Only if you want to read tools/list from a live server. -->
    <dependency>
        <groupId>io.github.mcpredteam</groupId>
        <artifactId>mcp-redteam-mcp</artifactId>
        <version>${mcp-redteam.version}</version>
        <scope>test</scope>
    </dependency>

    <!-- Yours to supply: mcp-redteam-mcp declares this `provided`. -->
    <dependency>
        <groupId>io.modelcontextprotocol.sdk</groupId>
        <artifactId>mcp</artifactId>
        <version>${mcp-sdk.version}</version>
        <scope>test</scope>
    </dependency>

    <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter</artifactId>
        <version>${junit.version}</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

Working copy: [`examples/scan-only/pom.xml`](../../examples/scan-only/pom.xml).

### Agent in the loop

Seven dependencies, a model provider, and something to run the model.

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>org.springframework.ai</groupId>
            <artifactId>spring-ai-bom</artifactId>
            <version>2.0.0</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>io.github.mcpredteam</groupId>
        <artifactId>mcp-redteam-junit</artifactId>
        <version>${mcp-redteam.version}</version>
        <scope>test</scope>
    </dependency>
    <dependency>
        <groupId>io.github.mcpredteam</groupId>
        <artifactId>mcp-redteam-spring-ai</artifactId>
        <version>${mcp-redteam.version}</version>
        <scope>test</scope>
    </dependency>

    <!-- The four below are the `provided` bill. -->

    <!-- ChatClient itself. Not transitive from a model module: those depend on spring-ai-model,
         while the fluent client lives in its own artifact that normally only the Boot starter
         pulls in. -->
    <dependency>
        <groupId>org.springframework.ai</groupId>
        <artifactId>spring-ai-client-chat</artifactId>
        <scope>test</scope>
    </dependency>

    <!-- Your model provider: spring-ai-openai, spring-ai-anthropic, spring-ai-ollama, … -->
    <dependency>
        <groupId>org.springframework.ai</groupId>
        <artifactId>spring-ai-ollama</artifactId>
        <scope>test</scope>
    </dependency>

    <!-- SyncMcpToolCallbackProvider, for tools discovered from a live MCP server. -->
    <dependency>
        <groupId>org.springframework.ai</groupId>
        <artifactId>spring-ai-mcp</artifactId>
        <scope>test</scope>
    </dependency>

    <dependency>
        <groupId>io.modelcontextprotocol.sdk</groupId>
        <artifactId>mcp</artifactId>
        <version>${mcp-sdk.version}</version>
        <scope>test</scope>
    </dependency>

    <dependency>
        <groupId>org.junit.jupiter</groupId>
        <artifactId>junit-jupiter</artifactId>
        <version>${junit.version}</version>
        <scope>test</scope>
    </dependency>
</dependencies>
```

Working copy: [`examples/agent/pom.xml`](../../examples/agent/pom.xml).

## Gradle

```kotlin
dependencies {
    testImplementation("io.github.mcpredteam:mcp-redteam-junit:0.1.0")

    // Live-server scanning
    testImplementation("io.github.mcpredteam:mcp-redteam-mcp:0.1.0")
    testImplementation("io.modelcontextprotocol.sdk:mcp:2.0.0")      // provided by you

    // Agent testing
    testImplementation("io.github.mcpredteam:mcp-redteam-spring-ai:0.1.0")
    testImplementation("org.springframework.ai:spring-ai-client-chat:2.0.0")
    testImplementation("org.springframework.ai:spring-ai-ollama:2.0.0")
    testImplementation("org.springframework.ai:spring-ai-mcp:2.0.0")

    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test { useJUnitPlatform() }
```

Gradle maps Maven's `provided` to `compileOnly` semantics on the producing side, so the same rule
applies: the SDK and Spring AI lines above are yours to declare.

## Keeping model-backed tests out of the default build

Anything that calls a real model should not run in a normal `mvn test`. Tag it and exclude the tag
in the build, not with `@Disabled` on each class — that kind rots, because someone adds a test,
forgets the annotation, and CI quietly starts depending on a model being reachable.

```java
@Tag("live")
class AgentHijackTest {
    // every test in here needs a model
}
```

```xml
<properties>
    <!-- Indirected through a property on purpose: a literal inside the plugin's <configuration>
         cannot be overridden from the command line at all, because POM configuration beats -D. -->
    <test.excludedGroups>live</test.excludedGroups>
</properties>

<profiles>
    <profile>
        <id>live</id>
        <properties>
            <test.excludedGroups/>
        </properties>
    </profile>
</profiles>

<build>
    <plugins>
        <plugin>
            <groupId>org.apache.maven.plugins</groupId>
            <artifactId>maven-surefire-plugin</artifactId>
            <version>3.5.2</version>
            <configuration>
                <excludedGroups>${test.excludedGroups}</excludedGroups>
            </configuration>
        </plugin>
    </plugins>
</build>
```

Then `mvn test` is fast and green everywhere, and `mvn test -Plive` runs the model-backed set.

Use the profile rather than `-DexcludedGroups=`. Two traps it avoids: Surefire's POM configuration
beats a command-line `-D`, so `-DexcludedGroups=` is **silently ignored** and you get a green build
that ran nothing; and PowerShell mangles a `-D` argument containing a dot or ending in a bare `=`.

## Published artifacts

All under `io.github.mcpredteam`, version `0.1.0`, on
[Maven Central](https://central.sonatype.com/namespace/io.github.mcpredteam):
`mcp-redteam-parent`, `mcp-redteam-core`, `mcp-redteam-junit`, `mcp-redteam-mcp`,
`mcp-redteam-spring-ai`.
