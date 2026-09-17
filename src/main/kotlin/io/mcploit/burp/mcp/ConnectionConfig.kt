package io.mcploit.burp.mcp

import java.nio.charset.StandardCharsets
import java.util.Base64

enum class AuthKind { NONE, BEARER, BASIC }

data class HeaderEntry(
    val name: String,
    val value: String,
    val enabled: Boolean = true,
)

/**
 * Everything needed to open one session, in one object.
 *
 * Kept serialisable so it can round-trip through Burp's persistence store as a
 * saved profile.
 */
data class ConnectionConfig(
    val name: String = "",
    val url: String = "http://127.0.0.1:8000/mcp",
    val transport: TransportKind = TransportKind.AUTO,
    val timeoutSeconds: Long = 30,
    val protocolVersion: String = PREFERRED_PROTOCOL,
    val authKind: AuthKind = AuthKind.NONE,
    val bearerToken: String = "",
    val basicUser: String = "",
    val basicPassword: String = "",
    val headers: List<HeaderEntry> = emptyList(),
    val sendInitializedNotification: Boolean = true,
) {

    /**
     * Auth first, then explicit headers, so a hand-written Authorization row
     * beats the auth section. That ordering is deliberate: when you are testing
     * a malformed or downgraded credential, the explicit row is the thing you
     * are actually trying to send.
     */
    fun effectiveHeaders(): Map<String, String> {
        val result = LinkedHashMap<String, String>()

        when (authKind) {
            AuthKind.BEARER -> {
                if (bearerToken.isNotBlank()) {
                    result["Authorization"] = "Bearer ${bearerToken.trim()}"
                }
            }
            AuthKind.BASIC -> {
                val raw = "$basicUser:$basicPassword"
                val encoded = Base64.getEncoder()
                    .encodeToString(raw.toByteArray(StandardCharsets.UTF_8))
                result["Authorization"] = "Basic $encoded"
            }
            AuthKind.NONE -> {
                // nothing
            }
        }

        for (entry in headers) {
            if (!entry.enabled) continue
            if (entry.name.isBlank()) continue
            result[entry.name.trim()] = entry.value
        }

        return result
    }

    /** Compact description for the connected status bar. */
    fun summary(): String {
        val parts = mutableListOf<String>()

        parts.add(
            when (transport) {
                TransportKind.STREAMABLE_HTTP -> "Streamable HTTP"
                TransportKind.SSE -> "HTTP + SSE"
                TransportKind.AUTO -> "auto"
            }
        )

        when (authKind) {
            AuthKind.BEARER -> parts.add("bearer")
            AuthKind.BASIC -> parts.add("basic")
            AuthKind.NONE -> {
                // omit rather than say "no auth", the absence is the signal
            }
        }

        val active = headers.count { it.enabled && it.name.isNotBlank() }
        if (active > 0) parts.add(if (active == 1) "1 header" else "$active headers")

        if (protocolVersion != PREFERRED_PROTOCOL) parts.add("protocol $protocolVersion")

        return parts.joinToString("  |  ")
    }

    val timeoutMillis: Long
        get() = timeoutSeconds * 1000L
}
