package io.mcploit.burp.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.JsonArray
import com.google.gson.JsonObject

const val CLIENT_NAME = "MCPloit"
const val CLIENT_VERSION = "0.1.0"
const val PREFERRED_PROTOCOL = "2025-06-18"

/** Pages of one list method to walk before giving up on a server's paging. */
private const val MAX_PAGES = 50

enum class TransportKind { AUTO, STREAMABLE_HTTP, SSE }

data class McpTool(
    val name: String,
    val description: String,
    val inputSchema: JsonObject?,
    val raw: JsonObject,
) {
    override fun toString(): String = name
}

data class McpResource(
    val uri: String,
    val name: String,
    val description: String,
    val mimeType: String,
    val isTemplate: Boolean,
    val raw: JsonObject,
) {
    override fun toString(): String =
        if (isTemplate) "$uri  (template)" else uri
}

data class McpPrompt(
    val name: String,
    val description: String,
    val arguments: JsonArray?,
    val raw: JsonObject,
) {
    override fun toString(): String = name
}

data class Catalog(
    val tools: List<McpTool>,
    val resources: List<McpResource>,
    val prompts: List<McpPrompt>,
)

data class ServerInfo(
    val name: String,
    val version: String,
    val protocolVersion: String,
    val capabilities: JsonObject?,
    val instructions: String,
)

/**
 * One connection to one MCP server.
 *
 * Everything here blocks. Call it from a worker thread.
 */
class McpSession(
    private val api: MontoyaApi,
    val config: ConnectionConfig,
    private val log: (String) -> Unit,
) {

    // Derived views so the rest of this class reads unchanged.
    private val url: String get() = config.url
    private val kind: TransportKind get() = config.transport
    private val extraHeaders: Map<String, String> get() = config.effectiveHeaders()
    private val timeoutMillis: Long get() = config.timeoutMillis

    private val ids = IdGenerator()
    private var transport: McpTransport? = null

    var serverInfo: ServerInfo? = null
        private set

    val transportName: String
        get() = transport?.name ?: "none"

    fun lastRequest(): HttpRequest? = transport?.lastRequest()

    /** Performs transport setup plus the MCP initialize handshake. */
    fun connect(): ServerInfo {
        val chosen = when (kind) {
            TransportKind.STREAMABLE_HTTP -> listOf(TransportKind.STREAMABLE_HTTP)
            TransportKind.SSE -> listOf(TransportKind.SSE)
            TransportKind.AUTO -> guessOrder()
        }

        var lastFailure: Exception? = null

        for (candidate in chosen) {
            val attempt = build(candidate)
            try {
                log("[connect] trying ${attempt.name} against $url")
                attempt.open()
                val info = handshake(attempt)
                transport = attempt
                serverInfo = info
                log("[connect] ${info.name} ${info.version}, protocol ${info.protocolVersion}")
                return info
            } catch (e: McpErrorException) {
                // The server spoke this transport well enough to return a
                // JSON-RPC error object, so the transport is right and the
                // request content is what it objected to. Trying another
                // transport would only bury the real message.
                try {
                    attempt.close()
                } catch (ignored: Exception) {
                }
                log("[connect] ${attempt.name} rejected the request: ${e.message}")
                throw e
            } catch (e: Exception) {
                lastFailure = e
                log("[connect] ${attempt.name} failed: ${e.message}")
                try {
                    attempt.close()
                } catch (ignored: Exception) {
                }
            }
        }

        throw lastFailure ?: McpTransportException("Could not connect to $url")
    }

    /**
     * Ordering heuristic for AUTO. A path ending in /sse is the legacy
     * convention; everything else is far more likely to be Streamable HTTP now.
     * Both get tried either way, this only decides which goes first.
     */
    private fun guessOrder(): List<TransportKind> {
        val path = url.substringBefore('?').trimEnd('/')
        return if (path.endsWith("/sse", ignoreCase = true)) {
            listOf(TransportKind.SSE, TransportKind.STREAMABLE_HTTP)
        } else {
            listOf(TransportKind.STREAMABLE_HTTP, TransportKind.SSE)
        }
    }

    private fun build(candidate: TransportKind): McpTransport = when (candidate) {
        TransportKind.SSE -> SseTransport(api, url, extraHeaders, timeoutMillis, log)
        else -> StreamableHttpTransport(api, url, extraHeaders, timeoutMillis, log)
    }

    private fun handshake(active: McpTransport): ServerInfo {
        val clientInfo = JsonObject()
        clientInfo.addProperty("name", CLIENT_NAME)
        clientInfo.addProperty("version", CLIENT_VERSION)

        val params = JsonObject()
        params.addProperty("protocolVersion", config.protocolVersion)
        params.add("capabilities", JsonObject())
        params.add("clientInfo", clientInfo)

        val response = active.call(
            JsonRpc.request(ids.next(), "initialize", params),
            timeoutMillis,
        )

        if (JsonRpc.isError(response)) throw McpErrorException(response)

        val result = Json.obj(response, "result")
            ?: throw McpTransportException("initialize returned no result object")

        val negotiated = Json.str(result, "protocolVersion", config.protocolVersion)
        when (active) {
            is StreamableHttpTransport -> active.rememberProtocolVersion(negotiated)
            is SseTransport -> active.rememberProtocolVersion(negotiated)
        }

        val info = Json.obj(result, "serverInfo")

        // Required by spec. Skipping it leaves some implementations in a state
        // where list calls come back empty, which is why it is a toggle rather
        // than a constant: that difference is worth being able to observe.
        if (config.sendInitializedNotification) {
            // Advisory. initialize already succeeded, so a server that rejects
            // or ignores this must not cost us an otherwise working session.
            try {
                active.send(JsonRpc.notification("notifications/initialized", null))
            } catch (e: Exception) {
                log("[connect] notifications/initialized was not accepted: ${e.message}")
            }
        }

        return ServerInfo(
            name = Json.str(info, "name", "unknown"),
            version = Json.str(info, "version", ""),
            protocolVersion = negotiated,
            capabilities = Json.obj(result, "capabilities"),
            instructions = Json.str(result, "instructions", ""),
        )
    }

    /** Sends an arbitrary method. Used by the raw JSON-RPC panel. */
    fun rawCall(method: String, params: JsonObject?): JsonObject {
        val response = rawCallAllowingError(method, params)
        if (JsonRpc.isError(response)) throw McpErrorException(response)
        return response
    }

    /** Same as rawCall but hands back JSON-RPC errors instead of throwing. */
    fun rawCallAllowingError(method: String, params: JsonObject?): JsonObject =
        withSessionRecovery {
            val active = transport ?: throw McpTransportException("Not connected")
            // A fresh id per attempt. Replaying the id from the call the server
            // refused would leave the retry indistinguishable from it in Burp's
            // history and in the log.
            active.call(JsonRpc.request(ids.next(), method, params), timeoutMillis)
        }

    /**
     * Replays a call once across a lost session.
     *
     * Sessions die for reasons unrelated to the request: an idle timeout, a
     * server restart mid-engagement, or a competing client's teardown. Without
     * this the session goes dead silently and every later call fails with a
     * message that points at the request, so the tool looks broken when only the
     * session id is stale. The re-handshake is logged rather than hidden,
     * because a session dropping on a specific payload is itself a result worth
     * seeing.
     */
    private fun <T> withSessionRecovery(block: () -> T): T {
        return try {
            block()
        } catch (e: McpSessionLostException) {
            val active = transport ?: throw e
            log("[session] server rejected the session (${e.message}); re-initialising once")

            (active as? StreamableHttpTransport)?.forgetSession()

            serverInfo = try {
                handshake(active)
            } catch (retry: Exception) {
                log("[session] re-initialise failed: ${retry.message}")
                throw e
            }

            log("[session] re-initialised, replaying the call")
            block()
        }
    }

    fun enumerate(): Catalog {
        return Catalog(
            tools = listTools(),
            resources = listResources() + listResourceTemplates(),
            prompts = listPrompts(),
        )
    }

    private fun listTools(): List<McpTool> {
        val items = paginate("tools/list", "tools")
        return items.map { entry ->
            McpTool(
                name = Json.str(entry, "name"),
                description = Json.str(entry, "description"),
                inputSchema = Json.obj(entry, "inputSchema"),
                raw = entry,
            )
        }
    }

    private fun listResources(): List<McpResource> {
        val items = paginate("resources/list", "resources")
        return items.map { entry ->
            McpResource(
                uri = Json.str(entry, "uri"),
                name = Json.str(entry, "name"),
                description = Json.str(entry, "description"),
                mimeType = Json.str(entry, "mimeType"),
                isTemplate = false,
                raw = entry,
            )
        }
    }

    /**
     * Parameterised resources live behind a separate method and are invisible to
     * `resources/list`. A server can look like it exposes nothing while still
     * serving a template such as `db://{table}`.
     */
    private fun listResourceTemplates(): List<McpResource> {
        val items = paginate("resources/templates/list", "resourceTemplates")
        return items.map { entry ->
            McpResource(
                uri = Json.str(entry, "uriTemplate"),
                name = Json.str(entry, "name"),
                description = Json.str(entry, "description"),
                mimeType = Json.str(entry, "mimeType"),
                isTemplate = true,
                raw = entry,
            )
        }
    }

    private fun listPrompts(): List<McpPrompt> {
        val items = paginate("prompts/list", "prompts")
        return items.map { entry ->
            val arguments = entry.get("arguments")
            McpPrompt(
                name = Json.str(entry, "name"),
                description = Json.str(entry, "description"),
                arguments = if (arguments != null && arguments.isJsonArray) arguments.asJsonArray else null,
                raw = entry,
            )
        }
    }

    /**
     * Walks a paginated list method. Servers that do not implement the method
     * answer with a JSON-RPC error, which is a normal outcome rather than a
     * failure, so it yields an empty list.
     */
    private fun paginate(method: String, key: String): List<JsonObject> {
        val collected = mutableListOf<JsonObject>()
        var cursor: String? = null
        var pages = 0

        while (true) {
            if (pages++ >= MAX_PAGES) {
                // Silence here reads as "that is the whole catalog", which is
                // the one thing an enumeration must never say when it is not.
                log("[enumerate] $method stopped at $MAX_PAGES pages, the listing may be incomplete")
                break
            }

            val params = JsonObject()
            cursor?.let { params.addProperty("cursor", it) }

            val response = try {
                rawCallAllowingError(method, if (cursor == null) null else params)
            } catch (e: Exception) {
                log("[enumerate] $method failed: ${e.message}")
                return collected
            }

            if (JsonRpc.isError(response)) {
                log("[enumerate] $method not supported: ${JsonRpc.errorMessage(response)}")
                return collected
            }

            val result = Json.obj(response, "result") ?: return collected
            val array = result.get(key)
            if (array != null && array.isJsonArray) {
                array.asJsonArray.forEach { element ->
                    if (element.isJsonObject) collected.add(element.asJsonObject)
                }
            }

            // Primitive rather than non-null: asString throws on an object or
            // array, and that exception would escape enumerate() entirely and
            // cost the whole catalog rather than one page of one list.
            val next = result.get("nextCursor")
            val nextCursor = if (next != null && next.isJsonPrimitive) next.asString else null
            if (nextCursor == null) break
            if (nextCursor == cursor) {
                log("[enumerate] $method repeated cursor $nextCursor, stopping")
                break
            }
            cursor = nextCursor
        }

        return collected
    }

    fun callTool(name: String, arguments: JsonObject): JsonObject {
        val params = JsonObject()
        params.addProperty("name", name)
        params.add("arguments", arguments)
        return rawCallAllowingError("tools/call", params)
    }

    fun readResource(uri: String): JsonObject {
        val params = JsonObject()
        params.addProperty("uri", uri)
        return rawCallAllowingError("resources/read", params)
    }

    fun getPrompt(name: String, arguments: JsonObject): JsonObject {
        val params = JsonObject()
        params.addProperty("name", name)
        params.add("arguments", arguments)
        return rawCallAllowingError("prompts/get", params)
    }

    fun ping(): JsonObject = rawCallAllowingError("ping", null)

    fun disconnect() {
        try {
            transport?.close()
        } catch (ignored: Exception) {
        }
        transport = null
        serverInfo = null
    }
}
