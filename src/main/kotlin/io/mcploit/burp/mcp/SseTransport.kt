package io.mcploit.burp.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.google.gson.JsonObject
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpResponse as JdkHttpResponse
import java.time.Duration
import java.util.Collections
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * MCP HTTP+SSE transport (protocol revision 2024-11-05).
 *
 * The client opens a long-lived GET that stays open for the life of the
 * session. The server's first event is `endpoint`, carrying the URL that
 * client-to-server POSTs must target. Every response then arrives back over the
 * GET stream rather than in the POST response body, so requests and responses
 * have to be correlated by JSON-RPC id.
 *
 * Both the POSTs and the GET stream use the JDK client rather than
 * `api.http().sendRequest`. The stream never completes by design, which Burp's
 * blocking send cannot represent; the POSTs can come back as `text/event-stream`
 * inline, which Burp's send refuses to buffer ("Streaming response received").
 * The POSTs are still built as Burp `HttpRequest`s for Repeater and mirrored to
 * the site map; the GET stream carries only server output the Log tab shows.
 */
class SseTransport(
    private val api: MontoyaApi,
    private val sseUrl: String,
    private val extraHeaders: Map<String, String>,
    private val timeoutMillis: Long,
    private val log: (String) -> Unit,
) : McpTransport {

    override val name: String = "HTTP + SSE"

    /**
     * The long-lived GET. A redirect here is safe to hand to the JDK: there is
     * no body to lose on a method-changing hop, and its NORMAL policy withholds
     * credentials when the target origin changes.
     */
    private val streamClient: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(15))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()

    /**
     * The message POSTs, which must be redirected by hand.
     *
     * The JDK's NORMAL policy answers a 301, 302 or 303 by reissuing the request
     * as a GET with no body, so the JSON-RPC message is silently discarded and
     * the server never sees the call at all. What comes back to the operator is
     * a timeout naming the stream, which is the one place the problem is not.
     */
    private val postClient: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(15))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build()

    private val pending = ConcurrentHashMap<String, CompletableFuture<JsonObject>>()
    private val endpointReady = CompletableFuture<String>()

    /** Origins already reported as off-origin, so the log says it once each. */
    private val warned = Collections.synchronizedSet(mutableSetOf<String>())

    private var streamThread: Thread? = null
    private var protocolVersion: String? = null

    @Volatile
    private var running = false

    @Volatile
    private var last: HttpRequest? = null

    override fun lastRequest(): HttpRequest? = last

    override fun open() {
        running = true
        val thread = Thread({ readStream() }, "mcploit-sse-reader")
        thread.isDaemon = true
        streamThread = thread
        thread.start()
    }

    override fun close() {
        running = false
        streamThread?.interrupt()
        streamThread = null
        // Anything blocked in awaitEndpoint has to be released too, otherwise a
        // close during connect leaves that caller waiting out the full timeout
        // for an endpoint event that can no longer arrive.
        if (!endpointReady.isDone) {
            endpointReady.completeExceptionally(McpTransportException("Session closed"))
        }
        pending.values.forEach {
            it.completeExceptionally(McpTransportException("Session closed"))
        }
        pending.clear()
    }

    private fun readStream() {
        try {
            val builder = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(sseUrl))
                .header("Accept", "text/event-stream")
                .header("Cache-Control", "no-store")
                .GET()
            extraHeaders.forEach { (key, value) -> builder.header(key, value) }

            val response = streamClient.send(builder.build(), JdkHttpResponse.BodyHandlers.ofLines())

            if (response.statusCode() !in 200..299) {
                // Include what the server actually said. A bare status code here
                // sends you hunting for a transport bug when the body usually
                // names the real problem outright.
                val detail = try {
                    response.body().limit(5).toList().joinToString(" ").take(400)
                } catch (e: Exception) {
                    ""
                }
                endpointReady.completeExceptionally(
                    McpTransportException(
                        "SSE stream returned HTTP ${response.statusCode()} from $sseUrl" +
                            if (detail.isBlank()) "" else ": $detail"
                    )
                )
                return
            }

            var eventName = "message"
            val data = StringBuilder()

            val iterator = response.body().iterator()
            while (running && iterator.hasNext()) {
                val rawLine = iterator.next()

                if (rawLine.trimEnd('\r').isEmpty()) {
                    if (data.isNotEmpty()) {
                        // One unusable frame must not take the reader down with
                        // it. Losing the thread here would leave the session
                        // looking connected while every later call timed out.
                        try {
                            dispatch(eventName, data.toString())
                        } catch (e: Exception) {
                            log("[sse] discarded an unusable frame: ${describe(e)}")
                        }
                        data.setLength(0)
                    }
                    eventName = "message"
                    continue
                }

                val parsed = SseFrames.field(rawLine) ?: continue
                when (parsed.first) {
                    "event" -> eventName = parsed.second
                    "data" -> {
                        if (data.isNotEmpty()) data.append('\n')
                        data.append(parsed.second)
                    }
                    else -> {
                        // id / retry, not needed here
                    }
                }
            }
        } catch (e: Exception) {
            if (running) {
                log("[sse] stream ended: ${describe(e)}")
                if (!endpointReady.isDone) {
                    endpointReady.completeExceptionally(
                        McpTransportException("Could not open SSE stream at $sseUrl: ${describe(e)}", e)
                    )
                }
            }
        }
    }

    private fun dispatch(eventName: String, payload: String) {
        if (eventName == "endpoint") {
            val resolved = try {
                URI.create(sseUrl).resolve(payload.trim()).toString()
            } catch (e: Exception) {
                payload.trim()
            }
            log("[sse] message endpoint = $resolved")
            // The endpoint is whatever the server says it is, so it can name
            // another origin entirely. Worth saying plainly, because from here
            // on the POSTs go there without the operator's credentials.
            if (!sameOrigin(sseUrl, resolved)) {
                log("[sse] warning: the advertised endpoint is off the origin of $sseUrl")
            }
            endpointReady.complete(resolved)
            return
        }

        log("<-- $payload")

        val parsed = try {
            Json.parse(payload)
        } catch (e: Exception) {
            return
        }
        if (!parsed.isJsonObject) return
        val envelope = parsed.asJsonObject

        val idNode = envelope.get("id")
        if (idNode == null || idNode.isJsonNull) {
            // Server-initiated notification. Logged above, nothing waiting on it.
            return
        }

        // A server-initiated request numbers its ids independently of ours, so
        // one can collide with a call still in flight. Completing that call with
        // the server's question would render it as though it were the answer.
        if (isServerRequest(envelope)) {
            log("[sse] server-initiated ${Json.str(envelope, "method")} request, not answered")
            return
        }

        val id = idKey(idNode)
        if (id == null) {
            log("[sse] ignoring a response whose id is neither a string nor a number")
            return
        }

        pending.remove(id)?.complete(envelope)
    }

    override fun send(message: JsonObject) {
        val endpoint = awaitEndpoint(timeoutMillis)
        val body = Json.compact.toJson(message)
        log("--> $body")
        val response = postToEndpoint(endpoint, body, timeoutMillis)
        if (response.status !in 200..299) {
            throw McpTransportException("HTTP ${response.status} sending notification to $endpoint")
        }
    }

    override fun call(message: JsonObject, timeoutMillis: Long): JsonObject {
        // One budget for the whole call, not one per blocking step. Waiting the
        // full timeout for the endpoint and then the full timeout again for the
        // response makes a 30 second setting take a minute to fail.
        val deadline = System.nanoTime() + timeoutMillis.coerceAtLeast(1L) * 1_000_000L

        val endpoint = awaitEndpoint(remainingMillis(deadline))
        val id = idKey(message.get("id"))
            ?: throw McpTransportException("Cannot send a request whose id is not a string or number")
        val body = Json.compact.toJson(message)

        val future = CompletableFuture<JsonObject>()
        pending[id] = future

        log("--> $body")
        val response = try {
            postToEndpoint(endpoint, body, remainingMillis(deadline))
        } catch (e: Exception) {
            pending.remove(id)
            throw e
        }

        if (response.status !in 200..299) {
            pending.remove(id)
            throw McpTransportException(
                "HTTP ${response.status} posting to $endpoint\n${response.body}"
            )
        }

        // The 2024-11-05 transport nominally answers over the stream and returns
        // 202 here, but plenty of implementations reply inline instead. Without
        // this check those servers look like a hang until the timeout expires.
        val inline = Envelopes.find(response.body, response.contentType, id)
        if (inline != null) {
            pending.remove(id)
            log("<-- ${Json.compact.toJson(inline)}")
            return inline
        }

        return try {
            future.get(remainingMillis(deadline), TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            pending.remove(id)
            throw McpTransportException(
                "Timed out after ${timeoutMillis}ms waiting for id $id on the SSE stream"
            )
        } catch (e: ExecutionException) {
            // Unwrapped, so a closed session reads as "Session closed" rather
            // than as a bare ExecutionException with the reason one level down.
            pending.remove(id)
            val cause = e.cause
            throw if (cause is McpTransportException) cause
            else McpTransportException("SSE call for id $id failed: ${describe(cause ?: e)}", cause)
        } catch (e: InterruptedException) {
            pending.remove(id)
            Thread.currentThread().interrupt()
            throw McpTransportException("Interrupted while waiting for id $id")
        }
    }

    private fun remainingMillis(deadlineNanos: Long): Long =
        ((deadlineNanos - System.nanoTime()) / 1_000_000L).coerceAtLeast(1L)

    /** A parsed POST reply, decoupled from Burp's own HttpResponse type. */
    private class PostReply(val status: Int, val contentType: String, val body: String)

    /**
     * POSTs a client-to-server message, following redirects by hand.
     *
     * Sent on the JDK client, not `api.http().sendRequest`, because a server
     * that answers this POST inline with `text/event-stream` would make Burp's
     * stack throw "Streaming response received" rather than return a body. The
     * Burp `HttpRequest` is still built so "Send last to Repeater" works, and
     * the exchange is mirrored to the site map so it stays visible under
     * Target > Site map.
     */
    private fun postToEndpoint(endpoint: String, body: String, timeoutMillis: Long): PostReply {
        var target = endpoint
        var hops = 0

        while (true) {
            val headers = postHeaders(target)

            var burpRequest = HttpRequest.httpRequestFromUrl(target)
                .withMethod("POST")
                .withBody(body)
            headers.forEach { (key, value) -> burpRequest = burpRequest.withHeaderSet(key, value) }
            last = burpRequest

            val builder = java.net.http.HttpRequest.newBuilder()
                .uri(URI.create(target))
                .timeout(Duration.ofMillis(timeoutMillis.coerceAtLeast(1_000)))
            headers.forEach { (key, value) ->
                try {
                    builder.header(key, value)
                } catch (e: IllegalArgumentException) {
                    log("[warn] dropping restricted header $key")
                }
            }
            builder.method("POST", java.net.http.HttpRequest.BodyPublishers.ofString(body))

            val response = try {
                postClient.send(builder.build(), JdkHttpResponse.BodyHandlers.ofString())
            } catch (e: Exception) {
                throw McpTransportException("POST to $target failed: ${describe(e)}", e)
            }

            mirrorToSiteMap(burpRequest, response)

            if (response.statusCode() !in REDIRECT_CODES) {
                val contentType = response.headers().firstValue("Content-Type").orElse("")
                return PostReply(response.statusCode(), contentType, response.body())
            }

            if (hops >= MAX_REDIRECTS) {
                throw McpTransportException("Too many redirects starting at $endpoint")
            }

            val resolved = redirectTarget(target, response.headers().firstValue("Location").orElse(null))
            log("[redirect] ${response.statusCode()} $target -> $resolved")
            target = resolved
            hops++
        }
    }

    /** Headers for one message POST, scoped to wherever the URL now points. */
    private fun postHeaders(target: String): Map<String, String> {
        val headers = LinkedHashMap<String, String>()
        headers["Content-Type"] = "application/json"
        // The 2024-11-05 transport answers over the stream and does not require
        // this. Servers that also speak the newer transport on the same endpoint
        // do require it, and answer a POST without it with "406 Not Acceptable:
        // Client must accept both application/json and text/event-stream" rather
        // than anything naming the real cause.
        headers["Accept"] = "application/json, text/event-stream"
        protocolVersion?.let { headers["MCP-Protocol-Version"] = it }
        extraHeaders.forEach { (key, value) -> headers[key] = value }

        if (sameOrigin(sseUrl, target)) return headers

        val kept = withoutCredentials(headers, extraHeaders.keys)
        val dropped = headers.keys - kept.keys
        if (dropped.isNotEmpty() && warned.add(target)) {
            log("[sse] $target is off the origin of $sseUrl, withholding: ${dropped.joinToString(", ")}")
        }
        return kept
    }

    /** Best-effort site-map visibility for a POST that never went through Burp. */
    private fun mirrorToSiteMap(request: HttpRequest, response: JdkHttpResponse<String>) {
        try {
            val raw = StringBuilder("HTTP/1.1 ${response.statusCode()}\r\n")
            response.headers().map().forEach { (key, values) ->
                // The JDK already de-chunked and fully read the body, so the
                // original framing headers describe bytes Burp will never see.
                // A stale Content-Length in particular makes Burp truncate the
                // body it renders. Drop them and let Burp show what is there.
                if (key.lowercase() !in FRAMING_HEADERS && values.isNotEmpty()) {
                    raw.append(key).append(": ").append(values.first()).append("\r\n")
                }
            }
            raw.append("\r\n").append(response.body())

            val burpResponse = burp.api.montoya.http.message.responses.HttpResponse
                .httpResponse(raw.toString())
            api.siteMap().add(
                burp.api.montoya.http.message.HttpRequestResponse
                    .httpRequestResponse(request, burpResponse)
            )
        } catch (ignored: Exception) {
            // Visibility is a convenience, never a correctness requirement.
        }
    }

    private fun awaitEndpoint(timeoutMillis: Long): String {
        return try {
            endpointReady.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (e: TimeoutException) {
            throw McpTransportException(
                "No endpoint event received from $sseUrl within ${timeoutMillis}ms. " +
                    "The target may be a Streamable HTTP server, try that transport instead."
            )
        } catch (e: Exception) {
            val cause = e.cause
            if (cause is McpTransportException) throw cause
            throw McpTransportException("SSE handshake failed: ${describe(e)}", e)
        }
    }

    fun rememberProtocolVersion(version: String) {
        protocolVersion = version
    }
}
