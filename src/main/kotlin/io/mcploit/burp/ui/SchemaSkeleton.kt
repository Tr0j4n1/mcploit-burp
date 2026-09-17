package io.mcploit.burp.ui

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonNull
import com.google.gson.JsonObject
import com.google.gson.JsonPrimitive
import io.mcploit.burp.mcp.Json

/**
 * Turns a JSON Schema into a filled-in starting point for the argument editor.
 *
 * The goal is a body you can edit rather than one you have to write. Required
 * properties come first, types get plausible placeholders, and enums use their
 * first permitted value so the request is schema-valid on the first send.
 *
 * Local `$ref` is resolved and `anyOf`/`oneOf` picks its first non-null branch,
 * because the generators behind most MCP servers lean on both. Pydantic, which
 * is what FastMCP builds tool schemas with, emits a nested model as
 * `{"$ref": "#/$defs/Model"}` and an optional field as
 * `{"anyOf": [{...}, {"type": "null"}]}`. Neither carries a `type` member, so
 * without this they fall through to the string default and the prefill hands
 * you `""` where an object belongs.
 */
object SchemaSkeleton {

    /** Deep enough for real schemas, shallow enough to stop a $ref cycle. */
    private const val MAX_DEPTH = 6

    fun forSchema(schema: JsonObject?): String {
        if (schema == null) return "{}"

        val properties = Json.obj(schema, "properties")
            ?: return "{}"

        val ordered = LinkedHashSet<String>()
        requiredNames(schema).forEach { if (properties.has(it)) ordered.add(it) }
        properties.keySet().forEach { ordered.add(it) }

        val skeleton = JsonObject()
        for (key in ordered) {
            val definition = Json.obj(properties, key) ?: JsonObject()
            skeleton.add(key, placeholder(definition, schema, 0))
        }

        return Json.show(skeleton)
    }

    fun forPromptArguments(arguments: JsonArray?): String {
        if (arguments == null) return "{}"
        val skeleton = JsonObject()
        arguments.forEach { element ->
            if (!element.isJsonObject) return@forEach
            val argument = element.asJsonObject
            val name = Json.str(argument, "name")
            if (name.isNotEmpty()) skeleton.addProperty(name, "")
        }
        return Json.show(skeleton)
    }

    /** Human readable one-line summary of a property, for the detail pane. */
    fun describeProperties(schema: JsonObject?): String {
        if (schema == null) return "  (no input schema advertised)"

        val properties = Json.obj(schema, "properties")
        if (properties == null || properties.keySet().isEmpty()) {
            return "  (no parameters)"
        }

        val required = requiredNames(schema).toSet()

        val lines = StringBuilder()
        for (key in properties.keySet()) {
            val declared = Json.obj(properties, key) ?: JsonObject()
            // Resolved, so a $ref property reports the type of what it points at
            // rather than reporting nothing at all.
            val definition = effective(declared, schema, 0)
            val type = typeName(definition).ifEmpty { "any" }
            val flag = if (required.contains(key)) "required" else "optional"
            val description = Json.str(definition, "description")
                .ifEmpty { Json.str(declared, "description") }

            lines.append("  ").append(key)
                .append("  <").append(type).append(", ").append(flag).append(">")

            val enumNode = definition.get("enum")
            if (enumNode != null && enumNode.isJsonArray) {
                lines.append("  enum: ").append(enumNode.toString())
            }
            if (description.isNotEmpty()) {
                lines.append("\n      ").append(description.replace("\n", "\n      "))
            }
            lines.append('\n')
        }
        return lines.toString().trimEnd('\n')
    }

    /**
     * The `required` array, skipping anything that is not a string.
     *
     * `asString` throws outright on an object or array entry, and this runs on
     * the event thread from the selection listener, so an odd schema would take
     * the whole tool panel down rather than just prefill badly.
     */
    private fun requiredNames(schema: JsonObject): List<String> {
        val node = schema.get("required")
        if (node == null || !node.isJsonArray) return emptyList()
        return node.asJsonArray.mapNotNull { element ->
            if (element.isJsonPrimitive) element.asString else null
        }
    }

    /** Resolves $ref then collapses anyOf/oneOf/allOf down to one definition. */
    private fun effective(definition: JsonObject, root: JsonObject?, depth: Int): JsonObject {
        val resolved = dereference(definition, root)
        if (depth >= MAX_DEPTH) return resolved
        val chosen = branch(resolved) ?: return resolved
        return effective(chosen, root, depth + 1)
    }

    /**
     * Follows a chain of local `$ref`s. Remote refs are left alone: fetching a
     * schema from a URL the server chose is a request this tool should not make
     * on its own.
     */
    private fun dereference(definition: JsonObject, root: JsonObject?): JsonObject {
        var current = definition
        var hops = 0
        while (hops++ < 8) {
            val ref = Json.str(current, "\$ref")
            if (ref.isEmpty()) return current
            current = pointer(root, ref) ?: return current
        }
        return current
    }

    /** Resolves a local JSON pointer such as #/$defs/Foo or #/definitions/Foo. */
    private fun pointer(root: JsonObject?, ref: String): JsonObject? {
        if (root == null || !ref.startsWith("#/")) return null
        var node = root
        for (rawSegment in ref.removePrefix("#/").split('/')) {
            if (rawSegment.isEmpty()) continue
            val segment = rawSegment.replace("~1", "/").replace("~0", "~")
            node = Json.obj(node, segment) ?: return null
        }
        return node
    }

    /**
     * Picks one branch of a union.
     *
     * The null branch is never the useful prefill: `Optional[str]` arrives as
     * `anyOf: [{"type": "string"}, {"type": "null"}]`, and filling the argument
     * in with null tells you nothing about what the field wants.
     */
    private fun branch(definition: JsonObject): JsonObject? {
        for (key in listOf("anyOf", "oneOf", "allOf")) {
            val node = definition.get(key) ?: continue
            if (!node.isJsonArray) continue
            val candidates = node.asJsonArray
                .filter { it.isJsonObject }
                .map { it.asJsonObject }
            if (candidates.isEmpty()) continue
            return candidates.firstOrNull { Json.str(it, "type") != "null" } ?: candidates.first()
        }
        return null
    }

    /** The declared type, tolerating the `["string", "null"]` array form. */
    private fun typeName(definition: JsonObject): String {
        val node = definition.get("type") ?: return ""
        if (node.isJsonPrimitive) return node.asString
        if (node.isJsonArray) {
            return node.asJsonArray
                .firstOrNull { it.isJsonPrimitive && it.asString != "null" }
                ?.asString
                .orEmpty()
        }
        return ""
    }

    private fun placeholder(declared: JsonObject, root: JsonObject?, depth: Int): JsonElement {
        if (depth > MAX_DEPTH) return JsonNull.INSTANCE

        val definition = effective(declared, root, 0)

        // deepCopy throughout: these elements belong to the tool's own raw
        // declaration, which the detail pane still renders. Handing the editor a
        // live reference into it would let one edit rewrite the catalog.
        if (definition.has("default")) return definition.get("default").deepCopy()

        val enumNode = definition.get("enum")
        if (enumNode != null && enumNode.isJsonArray && enumNode.asJsonArray.size() > 0) {
            return enumNode.asJsonArray.get(0).deepCopy()
        }

        val type = typeName(definition).ifEmpty {
            // An untyped definition that carries properties is an object in all
            // but the declaration.
            if (definition.has("properties")) "object" else "string"
        }

        return when (type) {
            "string" -> JsonPrimitive("")
            "integer" -> JsonPrimitive(0)
            "number" -> JsonPrimitive(0)
            "boolean" -> JsonPrimitive(false)
            "null" -> JsonNull.INSTANCE
            "array" -> {
                val array = JsonArray()
                val items = Json.obj(definition, "items")
                if (items != null) array.add(placeholder(items, root, depth + 1))
                array
            }
            "object" -> {
                val nested = JsonObject()
                val properties = Json.obj(definition, "properties")
                properties?.keySet()?.forEach { key ->
                    val child = Json.obj(properties, key) ?: JsonObject()
                    nested.add(key, placeholder(child, root, depth + 1))
                }
                nested
            }
            else -> JsonNull.INSTANCE
        }
    }
}
