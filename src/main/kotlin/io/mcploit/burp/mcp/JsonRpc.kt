package io.mcploit.burp.mcp

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import java.util.concurrent.atomic.AtomicLong

/** Shared Gson instances. Pretty for display, compact for the wire. */
object Json {
    val pretty: Gson = GsonBuilder()
        .setPrettyPrinting()
        .disableHtmlEscaping()
        .serializeNulls()
        .create()

    val compact: Gson = GsonBuilder()
        .disableHtmlEscaping()
        .create()

    fun parse(text: String): JsonElement = JsonParser.parseString(text)

    fun parseObject(text: String): JsonObject = JsonParser.parseString(text).asJsonObject

    fun show(element: JsonElement?): String =
        if (element == null) "" else pretty.toJson(element)

    /** Reads a string member, returning [fallback] when absent or null. */
    fun str(obj: JsonObject?, key: String, fallback: String = ""): String {
        if (obj == null) return fallback
        val member = obj.get(key) ?: return fallback
        if (member.isJsonNull) return fallback
        return if (member.isJsonPrimitive) member.asString else member.toString()
    }

    fun obj(parent: JsonObject?, key: String): JsonObject? {
        val member = parent?.get(key) ?: return null
        return if (member.isJsonObject) member.asJsonObject else null
    }
}

/** Monotonic JSON-RPC request ids, scoped to one session. */
class IdGenerator {
    private val counter = AtomicLong(0)
    fun next(): Long = counter.incrementAndGet()
}

/**
 * Canonical string form of a JSON-RPC id, or null when it cannot serve as one.
 *
 * Two problems are handled here rather than at every comparison site. A server
 * whose JSON stack routes numbers through a float hands back 1.0 for the 1 we
 * sent, and a raw `asString` comparison then never matches, so the response is
 * dropped and the call times out against a server that answered correctly.
 * Integral numbers are therefore normalised to their integer form. Separately,
 * `asString` throws outright on an object or array id, which a hostile or
 * broken server is free to send; returning null lets callers skip the envelope
 * instead of taking an exception from inside their own parsing.
 */
internal fun idKey(node: JsonElement?): String? {
    if (node == null || node.isJsonNull || !node.isJsonPrimitive) return null
    val primitive = node.asJsonPrimitive
    if (!primitive.isNumber) return primitive.asString
    val number = try {
        primitive.asBigDecimal
    } catch (e: NumberFormatException) {
        return primitive.asString
    }
    return try {
        number.toBigIntegerExact().toString()
    } catch (e: ArithmeticException) {
        number.stripTrailingZeros().toPlainString()
    }
}

/**
 * True when an envelope is a request the server sent us rather than an answer.
 *
 * JSON-RPC ids are only unique per direction, so a server-initiated request
 * (sampling, roots, elicitation) can legitimately carry the same id as a call
 * of ours that is still in flight. Without this check the two are matched to
 * each other and the server's question is rendered as though it were the reply.
 */
internal fun isServerRequest(envelope: JsonObject): Boolean =
    envelope.has("method") && !envelope.has("result") && !envelope.has("error")

object JsonRpc {

    fun request(id: Long, method: String, params: JsonObject?): JsonObject {
        val message = JsonObject()
        message.addProperty("jsonrpc", "2.0")
        message.addProperty("id", id)
        message.addProperty("method", method)
        if (params != null) message.add("params", params)
        return message
    }

    fun notification(method: String, params: JsonObject?): JsonObject {
        val message = JsonObject()
        message.addProperty("jsonrpc", "2.0")
        message.addProperty("method", method)
        if (params != null) message.add("params", params)
        return message
    }

    /** True when the envelope carries a JSON-RPC error rather than a result. */
    fun isError(response: JsonObject): Boolean =
        response.has("error") && !response.get("error").isJsonNull

    fun errorMessage(response: JsonObject): String {
        val error = Json.obj(response, "error") ?: return "unknown error"
        // Json.str tolerates null and non-primitive members; asString would
        // throw, turning a server error into an exception from our own
        // formatting code and losing the message entirely.
        val code = Json.str(error, "code", "?")
        val message = Json.str(error, "message", "unknown error")
        val data = Json.str(error, "data", "")
        return if (data.isEmpty()) "[$code] $message" else "[$code] $message: $data"
    }
}

/**
 * A never-null description of a throwable.
 *
 * Several JDK network exceptions (a refused connection, a reset socket) carry a
 * null message, so a bare `${e.message}` renders the literal "null" and buries
 * the one useful fact: what actually went wrong. Falling back to the class name
 * turns "failed: null" into "failed: ConnectException".
 */
internal fun describe(e: Throwable): String = e.message ?: e.javaClass.simpleName

/** Raised when the peer answers with a JSON-RPC error object. */
class McpErrorException(val response: JsonObject) :
    RuntimeException(JsonRpc.errorMessage(response))

/** Raised for transport level problems: no route, bad status, malformed frame. */
open class McpTransportException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/**
 * Raised when the server rejects the session id rather than the request.
 *
 * Distinct from the general transport failure because it is recoverable: a fresh
 * initialize hands back a working session and the call can be replayed. Without
 * this separation the session silently dies mid-engagement and every later call
 * fails with a message that points at the request rather than the session.
 */
class McpSessionLostException(message: String) : McpTransportException(message)
