package io.mcploit.burp.mcp

import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.JsonObject
import java.net.URI

/**
 * A channel that carries JSON-RPC messages to an MCP server.
 *
 * Implementations are expected to be usable from a single background worker
 * thread. Nothing here should ever be called on the Swing event thread.
 */
interface McpTransport {

    /** Label shown in the UI status bar. */
    val name: String

    /** Establishes the underlying channel. Does not perform the MCP handshake. */
    fun open()

    /** Sends a request and blocks until the matching response arrives. */
    fun call(message: JsonObject, timeoutMillis: Long): JsonObject

    /** Sends a notification. No response is expected. */
    fun send(message: JsonObject)

    /**
     * The most recent HTTP request this transport issued, so the UI can hand it
     * to Repeater. Null before the first exchange.
     */
    fun lastRequest(): HttpRequest?

    fun close()
}

/**
 * Sets a header whether or not the request already carries one.
 *
 * Neither Montoya method is safe on its own here. withAddedHeader appends a
 * duplicate when the header exists, and the server then reads whichever comes
 * first. withUpdatedHeader is a no-op when the header is absent, so the value
 * is dropped without complaint. httpRequestFromUrl supplies some headers and
 * not others, so which failure you get depends on the header name.
 */
internal fun HttpRequest.withHeaderSet(name: String, value: String): HttpRequest =
    if (hasHeader(name)) withUpdatedHeader(name, value) else withAddedHeader(name, value)

/**
 * Pulls JSON payloads out of a text/event-stream body.
 *
 * An SSE event is a run of field lines terminated by a blank line. Only the
 * concatenated `data:` fields carry the JSON-RPC message; `event:`, `id:`,
 * `retry:` and `:` comments are structural and get dropped.
 */
object SseFrames {

    fun extractDataPayloads(body: String): List<String> {
        val payloads = mutableListOf<String>()
        val current = StringBuilder()

        for (rawLine in body.lineSequence()) {
            val line = rawLine.trimEnd('\r')

            when {
                line.isEmpty() -> {
                    if (current.isNotEmpty()) {
                        payloads.add(current.toString())
                        current.setLength(0)
                    }
                }
                line.startsWith(":") -> {
                    // comment, ignore
                }
                line.startsWith("data:") -> {
                    // Spec strips exactly one leading space after the colon.
                    var value = line.substring(5)
                    if (value.startsWith(" ")) value = value.substring(1)
                    if (current.isNotEmpty()) current.append('\n')
                    current.append(value)
                }
                else -> {
                    // other field, ignore
                }
            }
        }

        if (current.isNotEmpty()) payloads.add(current.toString())
        return payloads
    }

    /** Splits one raw SSE line into field name and value, or null if malformed. */
    fun field(rawLine: String): Pair<String, String>? {
        val line = rawLine.trimEnd('\r')
        if (line.isEmpty() || line.startsWith(":")) return null
        val colon = line.indexOf(':')
        if (colon < 0) return Pair(line, "")
        var value = line.substring(colon + 1)
        if (value.startsWith(" ")) value = value.substring(1)
        return Pair(line.substring(0, colon), value)
    }
}

/** Redirect handling shared by both transports. */
internal const val MAX_REDIRECTS = 5
internal val REDIRECT_CODES = setOf(301, 302, 303, 307, 308)

/**
 * Headers that must not survive a hop to another origin.
 *
 * Following a redirect by hand is what lets a POST keep its method and body,
 * but it also opts out of the one thing the JDK's own redirect policy was doing
 * for free: withholding credentials when the target origin changes. A server
 * that answers with `307 Location: https://elsewhere/` would otherwise be
 * handed the operator's Authorization header, and this tool is pointed at
 * servers that have not earned that trust.
 */
internal val CREDENTIAL_HEADERS = setOf(
    "authorization",
    "proxy-authorization",
    "cookie",
    "mcp-session-id",
)

/**
 * Same scheme, host and port, with the default port filled in.
 *
 * Anything unparseable is reported as a different origin: failing closed costs
 * a header that could have been sent, failing open costs the credential.
 */
internal fun sameOrigin(a: String, b: String): Boolean = try {
    val left = URI(a)
    val right = URI(b)
    left.scheme.equals(right.scheme, ignoreCase = true) &&
        left.host.equals(right.host, ignoreCase = true) &&
        effectivePort(left) == effectivePort(right) &&
        left.host != null
} catch (e: Exception) {
    false
}

private fun effectivePort(uri: URI): Int =
    if (uri.port != -1) uri.port else when (uri.scheme?.lowercase()) {
        "https" -> 443
        "http" -> 80
        else -> -1
    }

/**
 * Strips credentials from a header set bound for another origin.
 *
 * User-supplied headers go too, in full: a tenant header is harmless but an
 * `X-Api-Key` is not, and nothing in the name tells the two apart. The caller
 * is expected to log what was withheld, because a request that silently loses
 * its auth looks like a server-side authorization bug from the outside.
 */
internal fun withoutCredentials(headers: Map<String, String>, userSupplied: Set<String>): Map<String, String> {
    val kept = LinkedHashMap<String, String>()
    for ((key, value) in headers) {
        val lower = key.lowercase()
        if (lower in CREDENTIAL_HEADERS) continue
        if (userSupplied.any { it.equals(key, ignoreCase = true) }) continue
        kept[key] = value
    }
    return kept
}

/** Resolves a Location header against the URL that produced it. */
internal fun redirectTarget(from: String, location: String?): String {
    if (location.isNullOrBlank()) {
        throw McpTransportException("Redirect from $from carried no Location header")
    }
    return try {
        URI.create(from).resolve(location).toString()
    } catch (e: Exception) {
        throw McpTransportException("Redirect from $from carried an unusable Location: $location")
    }
}

/**
 * Response headers that describe the wire framing of a body the JDK client has
 * already read and de-framed. Reusing them when rebuilding a response for Burp's
 * site map only misleads it — a Content-Length that no longer matches makes Burp
 * truncate what it renders.
 */
internal val FRAMING_HEADERS = setOf("content-length", "transfer-encoding")

/**
 * Recognising a server complaining about the session rather than the request.
 *
 * A Streamable HTTP server drops sessions for reasons that have nothing to do
 * with what was sent: an idle timeout, a restart, or our own DELETE on teardown.
 * The complaint arrives in three different shapes, and only one of them is even
 * valid JSON, so matching on the text is the only thing that covers all of them.
 *
 *   400 + {"id":"server-error","error":{"code":-32600,
 *          "message":"Bad Request: Missing session ID"}}
 *   400 + Bad Request: No valid session ID provided        <- plain text
 *   404 + {"id":"server-error","error":{"code":-32600,
 *          "message":"Not Found: Session has been terminated"}}
 *
 * Left unrecognised, the first shape is worse than an outright failure: the
 * envelope parses, so it gets handed back as though it were the answer to the
 * request, and the id on it is not even ours.
 */
object SessionLoss {

    private val MARKERS = listOf(
        "missing session id",
        "no valid session id",
        "session has been terminated",
        "session not found",
        "invalid session id",
    )

    private fun mentionsSession(text: String): Boolean {
        val haystack = text.lowercase()
        return MARKERS.any { haystack.contains(it) }
    }

    /** For a non-2xx response, where the body may or may not be JSON. */
    fun looksLost(status: Int, body: String): Boolean =
        (status == 400 || status == 404) && mentionsSession(body)

    /** For an error envelope that arrived with a 2xx, which some servers do. */
    fun looksLost(envelope: JsonObject): Boolean {
        if (!JsonRpc.isError(envelope)) return false
        return mentionsSession(JsonRpc.errorMessage(envelope))
    }
}

/**
 * Locating the answer to a request inside a response body.
 *
 * Shared by both transports, because a Streamable HTTP response and an inline
 * SSE POST reply have exactly the same shape problem: the body may be one JSON
 * envelope, or a run of SSE frames of which only one is ours.
 */
object Envelopes {

    fun candidates(body: String, contentType: String): List<String> =
        if (contentType.contains("text/event-stream", ignoreCase = true)) {
            SseFrames.extractDataPayloads(body)
        } else {
            listOf(body)
        }

    fun find(body: String, contentType: String, expectedId: String): JsonObject? {
        if (body.isBlank()) return null

        val frames = candidates(body, contentType)

        var nullIdError: JsonObject? = null
        var otherId: JsonObject? = null

        for (frame in frames) {
            val parsed = try {
                Json.parse(frame)
            } catch (e: Exception) {
                continue
            }
            if (!parsed.isJsonObject) continue
            val envelope = parsed.asJsonObject

            // A server is free to interleave its own requests into the same
            // stream, and its ids are numbered independently of ours, so one
            // can collide with the call being waited on here.
            if (isServerRequest(envelope)) continue

            val idNode = envelope.get("id")
            val hasId = idNode != null && !idNode.isJsonNull
            // Null rather than an exception for an object or array id, which
            // asString would throw on. See idKey.
            val key = if (hasId) idKey(idNode) else null

            if (key != null && key == expectedId) return envelope

            // JSON-RPC requires id to be null when the server could not parse or
            // validate the request at all, so a -32700 or -32600 arrives with no
            // id to match on. Treating that as "not found" would replace the
            // server's actual complaint with a misleading one of our own.
            if (!hasId && envelope.has("error") && nullIdError == null) {
                nullIdError = envelope
            }

            if (hasId && otherId == null) otherId = envelope
        }

        if (nullIdError != null) return nullIdError

        // A body holding exactly one envelope is the answer even if the id came
        // back with a coerced type.
        return if (frames.size == 1) otherId else null
    }
}
