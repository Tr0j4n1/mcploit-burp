# MCPloit Client for Burp Suite

A Burp extension that speaks MCP. Connect to a server, enumerate what it exposes,
and hand-craft calls against it from inside Burp.

This is the interaction half only. No detectors, no scanning, no payload library.
It is Repeater for a protocol Burp does not natively understand.

## Why it lives in Burp

Every client-to-server message is built as a Burp `HttpRequest`, so it can be
pushed to Repeater with one button, and every completed exchange is mirrored
into the site map (Target > Site map) for inspection and pivoting. There is no
proxy to configure and no CA to trust.

The actual send runs on the JDK HTTP client rather than `api.http().sendRequest`.
That is not a preference, it is forced: Burp's HTTP stack refuses to buffer a
streaming response, and a POST that comes back as `text/event-stream` throws
"Streaming response received" instead of returning a body. MCP servers answer
essentially every POST that way, so routing the send through Burp makes the
extension unable to talk to them at all. The consequence is that this traffic
appears in the site map but not in Proxy history, because it was never proxied.

## Build

Needs Gradle 8.x and a JDK 17 or later.

Do not use the `gradle` from apt on Debian or Kali. It is 4.4.1, which predates
Kotlin DSL support and will silently ignore both `.kts` files, leaving you with
an empty project and a confusing "task not found" error.

```bash
# One time: put a current Gradle in /opt
cd /tmp
wget https://services.gradle.org/distributions/gradle-8.10.2-bin.zip
sudo unzip -q -d /opt/gradle gradle-8.10.2-bin.zip
export PATH=/opt/gradle/gradle-8.10.2/bin:$PATH   # add to ~/.zshrc to persist

# Then, in the project directory
gradle wrapper --gradle-version 8.10.2
./gradlew shadowJar
```

Output lands at `build/libs/mcploit-burp.jar`.

Once the wrapper exists, `./gradlew` pins the version and the `/opt` entry no
longer needs to be on PATH.

If the build cannot resolve `montoya-api:2023.12.1`, bump the version in
`build.gradle.kts` to whatever matches your Burp release. Help > About shows the
build; the Montoya artifact tracks the same version scheme.

## Install

Burp > Extensions > Installed > Add > Extension type: Java > select the jar.

A new top-level **MCPloit** tab appears.

## Use

**Connect.** Enter the server URL and pick a transport.

- `Auto` tries Streamable HTTP first, unless the path ends in `/sse`, in which
  case it tries the legacy SSE transport first. Either way both get attempted.
- `Streamable HTTP` is the current transport (protocol 2025-03-26 onward). One
  endpoint, POST per message, responses inline as JSON or as SSE frames.
- `HTTP + SSE` is the 2024-11-05 transport. A long-lived GET carries responses,
  POSTs go to the endpoint the server advertises in its first event.

The `Headers` table takes one header per row, with a checkbox to keep a row
without sending it. Names and values are used exactly as typed: nothing is
split on commas and nothing is escaped, so a value containing a comma is one
value. Bearer tokens and basic credentials have their own section above it; a
header typed here under the same name wins, which is what you want when the
point of the test is a malformed or downgraded credential.

Duplicate names collapse, last row winning, because the sent set is a map. To
send the same header twice, push the request to Repeater and duplicate it there.

Credentials are withheld if a redirect carries a request off the origin you
typed, and the Log tab says so when it happens. The same applies to an SSE
server whose `endpoint` event advertises another origin.

**Enumerate.** On connect the extension runs `tools/list`, `resources/list`,
`resources/templates/list` and `prompts/list`, following `nextCursor` pagination
on each.

The templates call matters. Parameterised resources such as `db://{table}` do
not appear in `resources/list` at all, so a server can look like it exposes
nothing while still serving them. Templates are marked in the Resources tab and
you substitute the placeholders yourself before sending.

**Send.** Selecting a tool fills the argument box with a skeleton built from its
`inputSchema`: required properties first, enums pre-set to their first permitted
value, types given plausible placeholders. Edit it and press Send. The response
pane shows the full JSON-RPC envelope, error envelopes included, because an
error is frequently the interesting result.

For resources the argument box holds the URI as a plain string rather than JSON,
so there is no escaping to fight with.

**Raw method.** The `Raw method` field sends any JSON-RPC method with the
argument box as its `params`, verbatim. Use it for methods this UI does not wrap:
`logging/setLevel`, `completion/complete`, `resources/subscribe`, or anything
non-standard a given server has bolted on.

**Send last to Repeater.** Pushes the most recent HTTP request into a Repeater
tab, for byte-level edits the JSON editor will not let you express: malformed
envelopes, duplicated headers, wrong content types.

**Log tab.** Raw JSON-RPC in both directions, plus transport events such as the
negotiated session id and the SSE endpoint. Mirrored to the extension output
stream.

## Layout

```
McploitExtension.kt          entry point, registers the suite tab
mcp/JsonRpc.kt               envelope construction, Gson helpers, error types
mcp/McpTransport.kt          transport interface, SSE frame parsing
mcp/StreamableHttpTransport.kt
mcp/SseTransport.kt          background stream reader, id correlation
mcp/McpSession.kt            handshake, catalog enumeration, typed calls
ui/SchemaSkeleton.kt         JSON Schema to argument skeleton
ui/McpClientTab.kt           the tab
```

## Known gaps

- stdio servers are not supported. Everything here assumes HTTP.
- Server-initiated requests (sampling, roots, elicitation) are logged but not
  answered. A server that blocks waiting on one will hang until timeout.
- `resources/subscribe` works through the raw method field, but update
  notifications only show in the Log tab.
- OAuth flows are not implemented. Obtain a token elsewhere and paste it into
  the headers box.
