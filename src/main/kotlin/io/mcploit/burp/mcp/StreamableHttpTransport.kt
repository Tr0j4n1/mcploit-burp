package io.mcploit.burp.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.google.gson.JsonObject
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpResponse as JdkHttpResponse
import java.time.Duration
import java.util.Collections

/**
 * MCP Streamable HTTP transport (protocol revision 2025-03-26 and later).
 *
 * Every message is a POST to a single endpoint. The server answers either with
 * `application/json` holding one envelope, or with `text/event-stream` holding
 * one or more SSE frames that we drain to find the matching id.
 *
 * The send does NOT go through `api.http().sendRequest`, and cannot. Burp's HTTP
 * stack refuses to buffer a streaming response: a POST that comes back as
 * `text/event-stream` throws "Streaming response received" rather than returning
 * a body, and FastMCP answers essentially every POST that way. So the exchange
 * runs on the JDK client, exactly as the SSE transport's stream already does.
 *
 * What is preserved of the Burp integration:
 *   - the Burp `HttpRequest` is still built for every message, so `lastRequest()`
 *     and "Send last to Repeater" work unchanged;
 *   - each completed exchange is mirrored into Burp's site map, so the traffic
 *     is still visible under Target > Site map. It cannot appear in Proxy history,
 *     because it was never proxied.
 */
class StreamableHttpTransport(
    private val api: MontoyaApi,
    private val url: String,
    private val extraHeaders: Map<String, String>,
    private val timeoutMillis: Long,
    private val log: (String) -> Unit,
) : McpTransport {

    override val name: String = "Streamable HTTP"

    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(15))
        // Redirects are followed by hand below so the POST method and body are
        // preserved across a 307/308, which the JDK's own NORMAL policy would
        // downgrade to a GET on a 301/302. Doing it by hand also means doing the
        // part the JDK policy handled for free: see scopeToOrigin.
        .followRedirects(HttpClient.Redirect.NEVER)
        .build()

    private var sessionId: String? = null
    private var protocolVersion: String? = null

    /**
     * The endpoint actually in use. A server may redirect the configured URL
     * once (FastMCP answers /mcp with a 307 to /mcp/), and every later request
     * should go straight to the resolved form rather than pay the round trip
     * again and risk losing the body on a non-preserving hop.
     */
    private var currentUrl: String = url

    /** Origins already reported as off-origin, so the log says it once each. */
    private val warned = Collections.synchronizedSet(mutableSetOf<String>())

    @Volatile
    private var last: HttpRequest? = null

    /** A parsed exchange, decoupled from Burp's own HttpResponse type. */
    private class RawResponse(
        val status: Int,
        /** Header names lowercased for case-insensitive lookup. */
        val headers: Map<String, String>,
        val body: String,
    ) {
        fun header(name: String): String? = headers[name.lowercase()]
    }

    override fun open() {
        // Stateless. The session is established by the initialize exchange.
    }

    override fun lastRequest(): HttpRequest? = last

    override fun close() {
        val id = sessionId ?: return
        sessionId = null

        // A teardown aimed off-origin would have its session id stripped on the
        // way out, leaving a request that cannot terminate anything and only
        // tells a third party that the session existed.
        if (!sameOrigin(url, currentUrl)) {
            log("[session] skipping teardown, $currentUrl is off the origin of $url")
            return
        }

        // Best effort. Servers that do not implement it will 405, which is fine
        // and not worth surfacing to the user.
        try {
            val headers = LinkedHashMap<String, String>()
            headers["Mcp-Session-Id"] = id
            protocolVersion?.let { headers["MCP-Protocol-Version"] = it }
            extraHeaders.forEach { (key, value) -> headers[key] = value }
            exchange("DELETE", currentUrl, null, headers, timeoutMillis)
        } catch (ignored: Exception) {
            // Teardown is advisory.
        }
    }

    override fun send(message: JsonObject) {
        val body = Json.compact.toJson(message)
        log("--> $body")
        val response = post(body, timeoutMillis)
            ?: throw McpTransportException("No response from $currentUrl")

        // Same treatment as call(). A server is free to hand back a session id
        // on any response, notifications included, and skipping the capture here
        // means a rotation goes unnoticed until an unrelated call 404s.
        captureSessionId(response)

        if (response.status !in 200..299) {
            if (SessionLoss.looksLost(response.status, response.body)) {
                throw McpSessionLostException(
                    "HTTP ${response.status} sending notification to $currentUrl: ${response.body}"
                )
            }
            throw McpTransportException("HTTP ${response.status} sending notification to $currentUrl")
        }
    }

    override fun call(message: JsonObject, timeoutMillis: Long): JsonObject {
        // idKey rather than asString: an id we did not build ourselves could be
        // any JSON type, and asString throws on half of them.
        val expectedId = idKey(message.get("id"))
            ?: throw McpTransportException("Cannot send a request whose id is not a string or number")
        val body = Json.compact.toJson(message)
        log("--> $body")

        val response = post(body, timeoutMillis)
            ?: throw McpTransportException("No response from $currentUrl")

        captureSessionId(response)

        val status = response.status
        val responseBody = response.body

        if (status !in 200..299) {
            // Checked before the envelope recovery below, not after. The session
            // complaint arrives as a well formed error envelope carrying the id
            // "server-error", which recovery would happily hand back as if it
            // were the answer to this request.
            if (SessionLoss.looksLost(status, responseBody)) {
                throw McpSessionLostException("HTTP $status from $currentUrl: $responseBody")
            }

            // Some servers put a JSON-RPC error object in a 4xx body. Prefer that
            // over a bare status line, it is far more useful.
            val recovered = matchingEnvelope(response, expectedId)
            if (recovered != null) {
                log("<-- ${Json.compact.toJson(recovered)}")
                return recovered
            }
            throw McpTransportException("HTTP $status from $currentUrl\n$responseBody")
        }

        val envelope = matchingEnvelope(response, expectedId)
            ?: throw McpTransportException(
                "No JSON-RPC envelope with id $expectedId in the response body:\n$responseBody"
            )

        // A 200 carrying a session complaint. Rarer than the 4xx form but the
        // same recoverable condition, and it must not reach the caller as a
        // result for a request the server never actually ran.
        if (SessionLoss.looksLost(envelope)) {
            throw McpSessionLostException(
                "$currentUrl rejected the session: ${JsonRpc.errorMessage(envelope)}"
            )
        }

        log("<-- ${Json.compact.toJson(envelope)}")
        return envelope
    }

    /**
     * Drops the session id so the next exchange starts a new one.
     *
     * Called before a re-handshake: a dead id sent on `initialize` is rejected
     * by the same code path that killed the session in the first place.
     */
    fun forgetSession() {
        sessionId = null
    }

    private fun post(body: String, timeoutMillis: Long): RawResponse? {
        var hops = 0

        while (true) {
            val response = exchange("POST", currentUrl, body, messageHeaders(), timeoutMillis)
                ?: return null

            if (response.status !in REDIRECT_CODES) return response

            if (hops >= MAX_REDIRECTS) {
                throw McpTransportException("Too many redirects starting at $url")
            }

            val resolved = redirectTarget(currentUrl, response.header("Location"))
            log("[redirect] ${response.status} $currentUrl -> $resolved")
            currentUrl = resolved
            hops++
        }
    }

    /** Headers for one message POST, scoped to wherever the URL now points. */
    private fun messageHeaders(): Map<String, String> {
        val headers = LinkedHashMap<String, String>()
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json, text/event-stream"
        sessionId?.let { headers["Mcp-Session-Id"] = it }
        protocolVersion?.let { headers["MCP-Protocol-Version"] = it }
        extraHeaders.forEach { (key, value) -> headers[key] = value }
        return scopeToOrigin(currentUrl, headers)
    }

    /**
     * Withholds credentials once a redirect has carried us off the operator's
     * origin, and says so.
     *
     * Silence here would be the worst of both worlds: the request goes out
     * unauthenticated and the 401 that comes back looks like a server-side
     * authorization bug rather than a redirect we followed.
     */
    private fun scopeToOrigin(target: String, headers: Map<String, String>): Map<String, String> {
        if (sameOrigin(url, target)) return headers
        val kept = withoutCredentials(headers, extraHeaders.keys)
        val dropped = headers.keys - kept.keys
        if (dropped.isNotEmpty() && warned.add(target)) {
            log("[redirect] $target is off the origin of $url, withholding: ${dropped.joinToString(", ")}")
        }
        return kept
    }

    /**
     * One HTTP round trip on the JDK client. Also builds the Burp `HttpRequest`
     * so Repeater still works, and mirrors the exchange to the site map.
     */
    private fun exchange(
        method: String,
        target: String,
        body: String?,
        headers: Map<String, String>,
        timeoutMillis: Long,
    ): RawResponse? {
        // Built for Repeater and the site map, not for sending: Burp cannot send
        // it and receive the streaming reply. withHeaderSet keeps the template's
        // single Accept from being duplicated.
        var burpRequest = HttpRequest.httpRequestFromUrl(target).withMethod(method)
        if (body != null) burpRequest = burpRequest.withBody(body)
        headers.forEach { (key, value) -> burpRequest = burpRequest.withHeaderSet(key, value) }
        last = burpRequest

        val builder = java.net.http.HttpRequest.newBuilder()
            .uri(URI.create(target))
            .timeout(Duration.ofMillis(timeoutMillis.coerceAtLeast(1_000)))

        headers.forEach { (key, value) ->
            // The JDK forbids setting a handful of headers it manages itself
            // (Host, Content-Length, Connection). Skipping rather than throwing
            // keeps a stray one in the user's header box from killing the send.
            try {
                builder.header(key, value)
            } catch (e: IllegalArgumentException) {
                log("[warn] dropping restricted header $key")
            }
        }

        if (body == null) {
            builder.method(method, java.net.http.HttpRequest.BodyPublishers.noBody())
        } else {
            builder.method(method, java.net.http.HttpRequest.BodyPublishers.ofString(body))
        }

        val jdk = try {
            client.send(builder.build(), JdkHttpResponse.BodyHandlers.ofString())
        } catch (e: Exception) {
            throw McpTransportException("Request to $target failed: ${describe(e)}", e)
        }

        val flat = LinkedHashMap<String, String>()
        jdk.headers().map().forEach { (key, values) ->
            if (values.isNotEmpty()) flat[key.lowercase()] = values.first()
        }
        val response = RawResponse(jdk.statusCode(), flat, jdk.body())

        mirrorToSiteMap(burpRequest, response)
        return response
    }

    /**
     * Adds the exchange to Burp's site map so the operator can still see it, and
     * pivot from it, even though it never went through the proxy. Entirely best
     * effort: a parsing hiccup here must never fail the actual MCP call.
     */
    private fun mirrorToSiteMap(request: HttpRequest, response: RawResponse) {
        try {
            val raw = StringBuilder("HTTP/1.1 ${response.status}\r\n")
            response.headers.forEach { (key, value) ->
                // Header keys here are already lowercased. Drop the framing
                // headers: the body is fully read, so a stale Content-Length
                // would only make Burp truncate the site-map view.
                if (key !in FRAMING_HEADERS) raw.append(key).append(": ").append(value).append("\r\n")
            }
            raw.append("\r\n").append(response.body)

            val burpResponse: HttpResponse = HttpResponse.httpResponse(raw.toString())
            api.siteMap().add(HttpRequestResponse.httpRequestResponse(request, burpResponse))
        } catch (ignored: Exception) {
            // Visibility is a convenience, never a correctness requirement.
        }
    }

    private fun captureSessionId(response: RawResponse) {
        // Not latched on first sight. A server is free to rotate the session id
        // on any response, and silently continuing to send a stale one produces
        // a 404 several requests later with nothing pointing at the cause.
        val value = response.header("Mcp-Session-Id")
        if (value.isNullOrBlank()) return
        if (value == sessionId) return

        // An off-origin host must not get to choose the id we then send back to
        // the real one.
        if (!sameOrigin(url, currentUrl)) {
            log("[session] ignoring Mcp-Session-Id offered by $currentUrl, which is off origin")
            return
        }

        log(
            if (sessionId == null) "[session] Mcp-Session-Id = $value"
            else "[session] Mcp-Session-Id rotated to $value"
        )
        sessionId = value
    }

    /** Finds the envelope whose id matches, across json or event-stream bodies. */
    private fun matchingEnvelope(response: RawResponse, expectedId: String): JsonObject? {
        val contentType = response.header("Content-Type") ?: ""
        return Envelopes.find(response.body, contentType, expectedId)
    }

    /** Records the negotiated protocol version so later requests can echo it. */
    fun rememberProtocolVersion(version: String) {
        protocolVersion = version
    }
}
