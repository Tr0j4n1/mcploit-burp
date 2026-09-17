package io.mcploit.burp.ui

import com.google.gson.JsonArray
import com.google.gson.JsonObject
import io.mcploit.burp.mcp.Json
import io.mcploit.burp.mcp.JsonRpc

/**
 * Renders a JSON-RPC response for the response pane.
 *
 * The envelope alone is close to unreadable for the payloads that matter most.
 * A log resource or a command output comes back as a single JSON string with
 * every newline escaped, so the one thing worth looking at arrives as one very
 * long line. The decoded text goes first, the full envelope stays below it,
 * because both get read: the text to see the result, the envelope to see the
 * shape the server chose.
 */
object ResponseView {

    private const val RULE = "──────────────────────────────────────────────────────────────"

    fun render(response: JsonObject): String {
        val out = StringBuilder()

        if (JsonRpc.isError(response)) {
            out.append("JSON-RPC error  ").append(JsonRpc.errorMessage(response)).append('\n')
            out.append(RULE).append('\n')
            out.append(Json.show(response))
            return out.toString()
        }

        val result = Json.obj(response, "result")

        // tools/call reports failure inside a successful envelope. Rendering it
        // as a plain result hides the distinction entirely: the SSRF probe that
        // proves a port is closed and the one that proves it is open come back
        // in the same shape, differing only in this flag.
        if (result != null && isToolError(result)) {
            out.append("Tool reported an error  (result.isError = true)").append('\n')
            out.append(RULE).append('\n')
        }

        val text = extractText(result)
        if (text.isNotEmpty()) {
            out.append(text).append('\n')
            out.append(RULE).append('\n')
        }

        out.append(Json.show(response))
        return out.toString()
    }

    private fun isToolError(result: JsonObject): Boolean {
        val flag = result.get("isError") ?: return false
        return flag.isJsonPrimitive && flag.asJsonPrimitive.isBoolean && flag.asBoolean
    }

    /**
     * Pulls the human readable payload out of whichever shape the method uses.
     *
     * tools/call carries `content`, resources/read carries `contents`, and
     * prompts/get carries `messages` whose entries wrap a content object rather
     * than listing them flat.
     */
    private fun extractText(result: JsonObject?): String {
        if (result == null) return ""

        val parts = mutableListOf<String>()

        collect(result.get("content") as? JsonArray, parts)
        collect(result.get("contents") as? JsonArray, parts)

        (result.get("messages") as? JsonArray)?.forEach { element ->
            if (!element.isJsonObject) return@forEach
            val message = element.asJsonObject
            val role = Json.str(message, "role")
            val content = message.get("content")
            val rendered = when {
                content == null -> ""
                content.isJsonArray -> {
                    val nested = mutableListOf<String>()
                    collect(content.asJsonArray, nested)
                    nested.joinToString("\n")
                }
                content.isJsonObject -> one(content.asJsonObject)
                else -> ""
            }
            if (rendered.isNotEmpty()) {
                parts.add(if (role.isEmpty()) rendered else "[$role] $rendered")
            }
        }

        return parts.filter { it.isNotEmpty() }.joinToString("\n")
    }

    private fun collect(array: JsonArray?, into: MutableList<String>) {
        array?.forEach { element ->
            if (element.isJsonObject) {
                val rendered = one(element.asJsonObject)
                if (rendered.isNotEmpty()) into.add(rendered)
            }
        }
    }

    /** One content item. Text comes through as is, anything else is described. */
    private fun one(item: JsonObject): String {
        // Presence, not emptiness. A tool that legitimately returns "" is saying
        // something different from one that sent no text member at all, and
        // collapsing the two hides which of the pair you are looking at.
        val textNode = item.get("text")
        if (textNode != null && textNode.isJsonPrimitive) {
            val text = textNode.asString
            return if (text.isEmpty()) "[empty text member]" else text
        }

        val blob = Json.str(item, "blob")
        if (blob.isNotEmpty()) {
            val mime = Json.str(item, "mimeType", "application/octet-stream")
            return "[blob, $mime, ${blob.length} base64 chars]\n$blob"
        }

        // An image or an embedded resource has no text member. Say so rather
        // than silently contributing nothing, so an empty decoded section always
        // means the server sent no payload rather than that we skipped it.
        val type = Json.str(item, "type")
        return if (type.isEmpty()) "" else "[$type content, no text member]"
    }
}
