package io.mcploit.burp.ui

import burp.api.montoya.MontoyaApi
import com.google.gson.JsonObject
import io.mcploit.burp.mcp.Catalog
import io.mcploit.burp.mcp.ConnectionConfig
import io.mcploit.burp.mcp.Json
import io.mcploit.burp.mcp.McpPrompt
import io.mcploit.burp.mcp.McpResource
import io.mcploit.burp.mcp.McpSession
import io.mcploit.burp.mcp.McpTool
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.util.concurrent.Executors
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities

private const val TAB_TOOLS = 0
private const val TAB_RESOURCES = 1
private const val TAB_PROMPTS = 2

/** Log tab ceiling, and how much to keep when it is hit. */
private const val LOG_MAX_CHARS = 2_000_000
private const val LOG_KEEP_CHARS = 1_500_000

class McpClientTab(private val api: MontoyaApi) {

    private val worker = Executors.newSingleThreadExecutor { runnable ->
        val thread = Thread(runnable, "mcploit-worker")
        thread.isDaemon = true
        thread
    }

    private var session: McpSession? = null

    // Connection bar. Two states: a single button when idle, a live summary
    // plus session controls once connected.
    private var pendingConfig = ConnectionConfig()
    private val newConnectionButton = JButton("New Connection")
    private val urlLabel = JLabel()
    private val serverLabel = JLabel()
    private val editButton = JButton("Edit")
    private val reconnectButton = JButton("Reconnect")
    private val disconnectButton = JButton("Disconnect")
    private val pingButton = JButton("Ping")
    private val refreshButton = JButton("Refresh")
    private val statusLabel = JLabel("Not connected")
    private lateinit var connectionRow: JPanel

    // Catalog
    private val toolsModel = DefaultListModel<McpTool>()
    private val resourcesModel = DefaultListModel<McpResource>()
    private val promptsModel = DefaultListModel<McpPrompt>()
    private val toolsList = JList(toolsModel)
    private val resourcesList = JList(resourcesModel)
    private val promptsList = JList(promptsModel)
    private val catalogTabs = JTabbedPane()

    // Request and response
    private val detailArea = JTextArea()
    private val argumentLabel = JLabel("Arguments")
    private val argumentArea = JTextArea()
    private val responseArea = JTextArea()
    private val sendButton = JButton("Send")
    private val repeaterButton = JButton("Send last to Repeater")
    private val rawMethodField = JTextField("", 22)
    private val rawSendButton = JButton("Send raw method")

    private val logArea = JTextArea()

    val component: JPanel = build()

    // ---------------------------------------------------------------- layout

    private fun build(): JPanel {
        val mono = Font(Font.MONOSPACED, Font.PLAIN, 12)

        listOf(detailArea, argumentArea, responseArea, logArea).forEach {
            it.font = mono
        }
        detailArea.isEditable = false
        responseArea.isEditable = false
        logArea.isEditable = false
        argumentArea.lineWrap = false
        responseArea.lineWrap = true
        responseArea.wrapStyleWord = true

        toolsList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        resourcesList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        promptsList.selectionMode = ListSelectionModel.SINGLE_SELECTION

        toolsList.addListSelectionListener { if (!it.valueIsAdjusting) onToolSelected() }
        resourcesList.addListSelectionListener { if (!it.valueIsAdjusting) onResourceSelected() }
        promptsList.addListSelectionListener { if (!it.valueIsAdjusting) onPromptSelected() }

        catalogTabs.addTab("Tools", JScrollPane(toolsList))
        catalogTabs.addTab("Resources", JScrollPane(resourcesList))
        catalogTabs.addTab("Prompts", JScrollPane(promptsList))
        catalogTabs.addChangeListener { clearRequestPanes() }

        newConnectionButton.addActionListener { onNewConnectionPressed() }
        editButton.addActionListener { onEditPressed() }
        reconnectButton.addActionListener { onReconnectPressed() }
        disconnectButton.addActionListener { onDisconnectPressed() }
        pingButton.addActionListener { onPingPressed() }
        refreshButton.addActionListener { onRefreshPressed() }
        sendButton.addActionListener { onSendPressed() }
        repeaterButton.addActionListener { onRepeaterPressed() }
        rawSendButton.addActionListener { onRawSendPressed() }

        setConnected(false)

        // Two columns, split half and half. Every scroll pane gets a zero minimum
        // so each divider can travel the whole range and any region can be
        // collapsed to hand its space to another.

        // Selected-item details, which sit under the catalog in the left column.
        val detailPane = JScrollPane(detailArea)
        detailPane.border = BorderFactory.createTitledBorder("Selected item")
        detailPane.minimumSize = Dimension(0, 0)
        detailPane.preferredSize = Dimension(420, 240)

        // Arguments (the request), the top half of the right column.
        val argumentPane = JScrollPane(argumentArea)
        argumentPane.minimumSize = Dimension(0, 0)
        argumentPane.preferredSize = Dimension(500, 220)

        val argumentHeader = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        argumentHeader.add(argumentLabel)
        argumentHeader.add(sendButton)
        argumentHeader.add(repeaterButton)

        val argumentBlock = JPanel(BorderLayout())
        argumentBlock.minimumSize = Dimension(0, 0)
        argumentBlock.preferredSize = Dimension(500, 260)
        argumentBlock.border = BorderFactory.createTitledBorder("Request")
        argumentBlock.add(argumentHeader, BorderLayout.NORTH)
        argumentBlock.add(argumentPane, BorderLayout.CENTER)

        val rawRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        rawRow.add(JLabel("Raw method"))
        rawRow.add(rawMethodField)
        rawRow.add(rawSendButton)
        rawRow.add(JLabel("uses the params below verbatim"))
        argumentBlock.add(rawRow, BorderLayout.SOUTH)

        // Response, the bottom half of the right column.
        val responsePane = JScrollPane(responseArea)
        responsePane.border = BorderFactory.createTitledBorder("Response")
        responsePane.minimumSize = Dimension(0, 0)
        responsePane.preferredSize = Dimension(500, 260)

        // Left column: catalog table on top, selected-item details below it.
        val catalogPane = JPanel(BorderLayout())
        catalogPane.minimumSize = Dimension(0, 0)
        catalogPane.preferredSize = Dimension(420, 300)
        catalogPane.add(catalogTabs, BorderLayout.CENTER)

        val leftSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, catalogPane, detailPane)
        leftSplit.resizeWeight = 0.5
        leftSplit.isOneTouchExpandable = true

        // Right column: request over response, half and half.
        val rightSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, argumentBlock, responsePane)
        rightSplit.resizeWeight = 0.5
        rightSplit.isOneTouchExpandable = true

        // The two columns, half and half.
        val mainSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftSplit, rightSplit)
        mainSplit.resizeWeight = 0.5
        mainSplit.isOneTouchExpandable = true

        val clientPanel = JPanel(BorderLayout())
        clientPanel.add(connectionBar(), BorderLayout.NORTH)
        clientPanel.add(mainSplit, BorderLayout.CENTER)

        val logPanel = JPanel(BorderLayout())
        val logScroll = JScrollPane(logArea)
        logScroll.border = BorderFactory.createTitledBorder("JSON-RPC traffic")
        logPanel.add(logScroll, BorderLayout.CENTER)
        val clearLog = JButton("Clear")
        clearLog.addActionListener { logArea.text = "" }
        val logButtons = JPanel(FlowLayout(FlowLayout.LEFT))
        logButtons.add(clearLog)
        logPanel.add(logButtons, BorderLayout.SOUTH)

        val outer = JTabbedPane()
        outer.addTab("Client", clientPanel)
        outer.addTab("Log", logPanel)

        val root = JPanel(BorderLayout())
        root.add(outer, BorderLayout.CENTER)
        return root
    }

    private fun connectionBar(): JPanel {
        val row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 6))
        connectionRow = row

        urlLabel.font = urlLabel.font.deriveFont(Font.BOLD)
        serverLabel.foreground = Color(0x9A, 0x9A, 0x9A)

        row.add(newConnectionButton)
        row.add(urlLabel)
        row.add(serverLabel)
        row.add(editButton)
        row.add(reconnectButton)
        row.add(disconnectButton)
        row.add(pingButton)
        row.add(refreshButton)
        row.add(Box.createHorizontalStrut(12))
        row.add(statusLabel)
        return row
    }

    // ------------------------------------------------------------- lifecycle

    private fun onNewConnectionPressed() {
        val dialog = ConnectionDialog(component, "New Connection", pendingConfig)
        dialog.isVisible = true
        val chosen = dialog.result ?: return
        pendingConfig = chosen
        openSession(chosen)
    }

    private fun onEditPressed() {
        val dialog = ConnectionDialog(component, "Edit Connection", pendingConfig)
        dialog.isVisible = true
        val chosen = dialog.result ?: return
        pendingConfig = chosen
        // Editing implies you want the change to take effect, so reconnect.
        closeSession { openSession(chosen) }
    }

    private fun onReconnectPressed() {
        closeSession { openSession(pendingConfig) }
    }

    private fun onDisconnectPressed() {
        closeSession(null)
    }

    private fun closeSession(then: (() -> Unit)?) {
        val closing = session
        session = null
        worker.submit {
            closing?.disconnect()
            SwingUtilities.invokeLater {
                setConnected(false)
                statusLabel.text = "Not connected"
                toolsModel.clear()
                resourcesModel.clear()
                promptsModel.clear()
                clearRequestPanes()
                then?.invoke()
            }
        }
    }

    private fun openSession(config: ConnectionConfig) {
        newConnectionButton.isEnabled = false
        statusLabel.text = "Connecting..."

        worker.submit {
            val candidate = McpSession(api, config, this::log)
            try {
                val info = candidate.connect()
                val catalog = candidate.enumerate()
                SwingUtilities.invokeLater {
                    session = candidate
                    populate(catalog)
                    setConnected(true)
                    urlLabel.text = config.url
                    serverLabel.text =
                        "${info.name} ${info.version}  |  ${candidate.transportName}  |  " +
                            "protocol ${info.protocolVersion}  |  ${config.summary()}"
                    statusLabel.text =
                        "${catalog.tools.size} tools, ${catalog.resources.size} resources, " +
                            "${catalog.prompts.size} prompts"
                    if (info.instructions.isNotEmpty()) {
                        detailArea.text = "Server instructions:\n\n${info.instructions}"
                    }
                }
            } catch (e: Exception) {
                candidate.disconnect()
                SwingUtilities.invokeLater {
                    setConnected(false)
                    statusLabel.text = "Connect failed: ${firstLine(e.message)}"
                    responseArea.text = e.message ?: "Connection failed"
                    responseArea.caretPosition = 0
                }
            }
        }
    }

    private fun onRefreshPressed() {
        val active = session ?: return
        statusLabel.text = "Enumerating..."
        worker.submit {
            try {
                val catalog = active.enumerate()
                SwingUtilities.invokeLater {
                    populate(catalog)
                    statusLabel.text =
                        "${catalog.tools.size} tools, ${catalog.resources.size} resources, " +
                            "${catalog.prompts.size} prompts"
                }
            } catch (e: Exception) {
                SwingUtilities.invokeLater { statusLabel.text = "Refresh failed: ${e.message}" }
            }
        }
    }

    private fun onPingPressed() {
        val active = session ?: return
        worker.submit {
            val text = try {
                ResponseView.render(active.ping())
            } catch (e: Exception) {
                "ping failed: ${e.message}"
            }
            SwingUtilities.invokeLater { responseArea.text = text }
        }
    }

    private fun setConnected(connected: Boolean) {
        newConnectionButton.isVisible = !connected
        newConnectionButton.isEnabled = true

        urlLabel.isVisible = connected
        serverLabel.isVisible = connected
        editButton.isVisible = connected
        reconnectButton.isVisible = connected
        disconnectButton.isVisible = connected
        pingButton.isVisible = connected
        refreshButton.isVisible = connected

        sendButton.isEnabled = connected
        rawSendButton.isEnabled = connected
        repeaterButton.isEnabled = connected

        if (!connected) {
            urlLabel.text = ""
            serverLabel.text = ""
        }

        // build() calls this before the panel fields exist, so guard rather
        // than touch a lateinit that is not assigned yet.
        if (::connectionRow.isInitialized) {
            connectionRow.revalidate()
            connectionRow.repaint()
        }
    }

    private fun populate(catalog: Catalog) {
        toolsModel.clear()
        resourcesModel.clear()
        promptsModel.clear()
        catalog.tools.forEach { toolsModel.addElement(it) }
        catalog.resources.forEach { resourcesModel.addElement(it) }
        catalog.prompts.forEach { promptsModel.addElement(it) }
        catalogTabs.setTitleAt(TAB_TOOLS, "Tools (${catalog.tools.size})")
        catalogTabs.setTitleAt(TAB_RESOURCES, "Resources (${catalog.resources.size})")
        catalogTabs.setTitleAt(TAB_PROMPTS, "Prompts (${catalog.prompts.size})")
    }

    // -------------------------------------------------------------- selection

    private fun clearRequestPanes() {
        detailArea.text = ""
        argumentArea.text = ""
        argumentLabel.text = "Arguments"
    }

    private fun onToolSelected() {
        val tool = toolsList.selectedValue ?: return
        detailArea.text = buildString {
            append("tools/call  ->  ").append(tool.name).append("\n\n")
            if (tool.description.isNotEmpty()) append(tool.description).append("\n\n")
            append("Parameters:\n")
            append(SchemaSkeleton.describeProperties(tool.inputSchema)).append("\n\n")
            append("Raw declaration:\n")
            append(Json.show(tool.raw))
        }
        detailArea.caretPosition = 0
        argumentLabel.text = "Arguments (JSON object)"
        argumentArea.text = SchemaSkeleton.forSchema(tool.inputSchema)
    }

    private fun onResourceSelected() {
        val resource = resourcesList.selectedValue ?: return
        detailArea.text = buildString {
            append("resources/read  ->  ").append(resource.uri).append("\n\n")
            if (resource.name.isNotEmpty()) append("Name: ").append(resource.name).append("\n")
            if (resource.mimeType.isNotEmpty()) append("MIME: ").append(resource.mimeType).append("\n")
            if (resource.isTemplate) {
                append("\nThis is a URI template. Substitute the placeholders below before sending.\n")
            }
            if (resource.description.isNotEmpty()) append("\n").append(resource.description).append("\n")
            append("\nRaw declaration:\n")
            append(Json.show(resource.raw))
        }
        detailArea.caretPosition = 0
        argumentLabel.text = "Resource URI"
        argumentArea.text = resource.uri
    }

    private fun onPromptSelected() {
        val prompt = promptsList.selectedValue ?: return
        detailArea.text = buildString {
            append("prompts/get  ->  ").append(prompt.name).append("\n\n")
            if (prompt.description.isNotEmpty()) append(prompt.description).append("\n\n")
            append("Raw declaration:\n")
            append(Json.show(prompt.raw))
        }
        detailArea.caretPosition = 0
        argumentLabel.text = "Arguments (JSON object)"
        argumentArea.text = SchemaSkeleton.forPromptArguments(prompt.arguments)
    }

    // ----------------------------------------------------------------- send

    private fun onSendPressed() {
        val active = session ?: return

        when (catalogTabs.selectedIndex) {
            TAB_TOOLS -> {
                val tool = toolsList.selectedValue ?: return warn("Select a tool first")
                val arguments = parseArguments() ?: return
                dispatch { active.callTool(tool.name, arguments) }
            }
            TAB_RESOURCES -> {
                // Only the line structure is stripped, not the spaces. A trailing
                // space is significant in a payload such as `price://x'--%20` typed
                // literally, and trimming it turns a working SQL comment into a
                // broken one with nothing on screen to explain the difference.
                val uri = argumentArea.text.trim('\n', '\r')
                if (uri.isBlank()) return warn("Enter a resource URI")
                dispatch { active.readResource(uri) }
            }
            TAB_PROMPTS -> {
                val prompt = promptsList.selectedValue ?: return warn("Select a prompt first")
                val arguments = parseArguments() ?: return
                dispatch { active.getPrompt(prompt.name, arguments) }
            }
        }
    }

    private fun onRawSendPressed() {
        val active = session ?: return
        val method = rawMethodField.text.trim()
        if (method.isEmpty()) return warn("Enter a method name, for example resources/templates/list")

        // An empty box means "send no params at all"; a typed {} means "send an
        // empty params object". Collapsing the two removes the only way to test
        // the difference, and servers do treat an absent params differently from
        // an empty one.
        val body = argumentArea.text.trim()
        val params: JsonObject? = if (body.isEmpty()) {
            null
        } else {
            try {
                Json.parseObject(body)
            } catch (e: Exception) {
                return warn("params is not a JSON object: ${e.message}")
            }
        }

        dispatch { active.rawCallAllowingError(method, params) }
    }

    /**
     * Runs a call off the event thread and renders whatever comes back. JSON-RPC
     * errors are rendered rather than thrown, since an error envelope is often
     * exactly the interesting result.
     */
    private fun dispatch(call: () -> JsonObject) {
        responseArea.text = "Sending..."
        sendButton.isEnabled = false
        rawSendButton.isEnabled = false

        worker.submit {
            val rendered = try {
                ResponseView.render(call())
            } catch (e: Exception) {
                "Transport error: ${e.message}"
            }

            SwingUtilities.invokeLater {
                responseArea.text = rendered
                responseArea.caretPosition = 0
                sendButton.isEnabled = session != null
                rawSendButton.isEnabled = session != null
            }
        }
    }

    private fun onRepeaterPressed() {
        val request = session?.lastRequest()
        if (request == null) {
            warn("Nothing sent yet on this session")
            return
        }
        val label = session?.serverInfo?.name ?: "MCP"
        api.repeater().sendToRepeater(request, "MCP: $label")
        statusLabel.text = "Sent last request to Repeater"
    }

    // ---------------------------------------------------------------- helpers

    private fun parseArguments(): JsonObject? {
        val body = argumentArea.text.trim()
        if (body.isEmpty()) return JsonObject()
        return try {
            Json.parseObject(body)
        } catch (e: Exception) {
            warn("Arguments are not a JSON object: ${e.message}")
            null
        }
    }

    /** JLabel has no notion of line breaks, so keep the status bar to one. */
    private fun firstLine(message: String?): String {
        if (message.isNullOrBlank()) return "connection failed"
        val line = message.lineSequence().first().trim()
        return if (line.length <= 160) line else line.take(157) + "..."
    }

    private fun warn(message: String) {
        statusLabel.text = message
    }

    private fun log(line: String) {
        SwingUtilities.invokeLater {
            logArea.append(line)
            logArea.append("\n")
            trimLog()
            logArea.caretPosition = logArea.document.length
        }
        api.logging().logToOutput(line)
    }

    /**
     * Keeps the Log tab bounded.
     *
     * A long engagement against a chatty server otherwise grows this document
     * without limit inside Burp's own heap. Nothing is lost that matters: every
     * line went to the extension output stream on the way in.
     */
    private fun trimLog() {
        val document = logArea.document
        if (document.length <= LOG_MAX_CHARS) return
        try {
            document.remove(0, document.length - LOG_KEEP_CHARS)
        } catch (ignored: Exception) {
            // A failed trim is not worth interrupting the log for.
        }
    }

    fun shutdown() {
        session?.disconnect()
        session = null
        worker.shutdownNow()
    }
}
