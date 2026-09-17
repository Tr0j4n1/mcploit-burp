package io.mcploit.burp.ui

import io.mcploit.burp.mcp.AuthKind
import io.mcploit.burp.mcp.ConnectionConfig
import io.mcploit.burp.mcp.HeaderEntry
import io.mcploit.burp.mcp.PREFERRED_PROTOCOL
import io.mcploit.burp.mcp.TransportKind
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JPasswordField
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.table.DefaultTableModel

/**
 * Modal connection editor.
 *
 * Everything that is set once per session lives here rather than in the main
 * toolbar, which frees that row to show what is actually true right now.
 */
class ConnectionDialog(
    parent: Component,
    title: String,
    initial: ConnectionConfig,
) : JDialog(
    SwingUtilities.getWindowAncestor(parent),
    title,
    java.awt.Dialog.ModalityType.APPLICATION_MODAL,
) {

    /** Carried through untouched; the dialog does not edit it, but losing it
     *  on every edit would quietly empty a field the config declares. */
    private val configName = initial.name

    private val urlField = JTextField(initial.url, 40)
    private val transportBox = JComboBox(arrayOf("Auto", "Streamable HTTP", "HTTP + SSE"))
    private val timeoutField = JTextField(initial.timeoutSeconds.toString(), 5)
    private val protocolField = JTextField(initial.protocolVersion, 12)

    private val authBox = JComboBox(arrayOf("None", "Bearer token", "Basic"))
    private val bearerField = JTextField(initial.bearerToken, 34)
    private val basicUserField = JTextField(initial.basicUser, 16)
    private val basicPasswordField = JPasswordField(initial.basicPassword, 16)

    private val bearerLabel = JLabel("Token")
    private val basicUserLabel = JLabel("Username")
    private val basicPasswordLabel = JLabel("Password")

    private val initializedCheck =
        JCheckBox("Send notifications/initialized after handshake", initial.sendInitializedNotification)

    private val headerModel = object : DefaultTableModel(arrayOf("Use", "Name", "Value"), 0) {
        override fun getColumnClass(column: Int): Class<*> =
            if (column == 0) java.lang.Boolean::class.java else String::class.java
    }
    private val headerTable = JTable(headerModel)

    private val errorLabel = JLabel(" ")

    /** Null when the user cancelled. */
    var result: ConnectionConfig? = null
        private set

    init {
        transportBox.selectedIndex = when (initial.transport) {
            TransportKind.STREAMABLE_HTTP -> 1
            TransportKind.SSE -> 2
            TransportKind.AUTO -> 0
        }
        authBox.selectedIndex = when (initial.authKind) {
            AuthKind.BEARER -> 1
            AuthKind.BASIC -> 2
            AuthKind.NONE -> 0
        }
        initial.headers.forEach { entry ->
            headerModel.addRow(arrayOf(entry.enabled, entry.name, entry.value))
        }

        authBox.addActionListener { syncAuthFields() }
        syncAuthFields()

        val content = JPanel()
        content.layout = BoxLayout(content, BoxLayout.Y_AXIS)
        content.border = BorderFactory.createEmptyBorder(10, 10, 10, 10)
        content.add(targetPanel())
        content.add(Box.createVerticalStrut(8))
        content.add(authPanel())
        content.add(Box.createVerticalStrut(8))
        content.add(headersPanel())
        content.add(Box.createVerticalStrut(8))
        content.add(optionsPanel())

        errorLabel.foreground = java.awt.Color(0xC0, 0x39, 0x2B)

        val buttons = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 6))
        val cancel = JButton("Cancel")
        val connect = JButton("Connect")
        cancel.addActionListener { dispose() }
        connect.addActionListener { onConnect() }
        buttons.add(errorLabel)
        buttons.add(cancel)
        buttons.add(connect)

        layout = BorderLayout()
        add(content, BorderLayout.CENTER)
        add(buttons, BorderLayout.SOUTH)

        rootPane.defaultButton = connect
        pack()
        setLocationRelativeTo(parent)
    }

    // ------------------------------------------------------------- sections

    private fun targetPanel(): JPanel {
        val panel = JPanel(GridBagLayout())
        panel.border = BorderFactory.createTitledBorder("Target")
        val c = GridBagConstraints()
        c.insets = Insets(3, 4, 3, 4)
        c.anchor = GridBagConstraints.WEST

        c.gridx = 0; c.gridy = 0
        panel.add(JLabel("URL"), c)
        c.gridx = 1; c.gridwidth = 3; c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0
        panel.add(urlField, c)

        c.gridwidth = 1; c.fill = GridBagConstraints.NONE; c.weightx = 0.0
        c.gridx = 0; c.gridy = 1
        panel.add(JLabel("Transport"), c)
        c.gridx = 1
        panel.add(transportBox, c)
        c.gridx = 2
        panel.add(JLabel("Timeout (s)"), c)
        c.gridx = 3
        panel.add(timeoutField, c)

        c.gridx = 0; c.gridy = 2
        panel.add(JLabel("Protocol version"), c)
        c.gridx = 1
        panel.add(protocolField, c)
        c.gridx = 2; c.gridwidth = 2
        panel.add(JLabel("edit to test version downgrade handling"), c)

        return panel
    }

    private fun authPanel(): JPanel {
        val panel = JPanel(GridBagLayout())
        panel.border = BorderFactory.createTitledBorder("Authentication")
        val c = GridBagConstraints()
        c.insets = Insets(3, 4, 3, 4)
        c.anchor = GridBagConstraints.WEST

        c.gridx = 0; c.gridy = 0
        panel.add(JLabel("Scheme"), c)
        c.gridx = 1
        panel.add(authBox, c)

        c.gridx = 0; c.gridy = 1
        panel.add(bearerLabel, c)
        c.gridx = 1; c.gridwidth = 3; c.fill = GridBagConstraints.HORIZONTAL; c.weightx = 1.0
        panel.add(bearerField, c)

        c.gridwidth = 1; c.fill = GridBagConstraints.NONE; c.weightx = 0.0
        c.gridx = 0; c.gridy = 2
        panel.add(basicUserLabel, c)
        c.gridx = 1
        panel.add(basicUserField, c)
        c.gridx = 2
        panel.add(basicPasswordLabel, c)
        c.gridx = 3
        panel.add(basicPasswordField, c)

        return panel
    }

    private fun headersPanel(): JPanel {
        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createTitledBorder("Headers (sent on every request)")

        headerTable.rowHeight = 22
        headerTable.columnModel.getColumn(0).preferredWidth = 34
        headerTable.columnModel.getColumn(0).maxWidth = 40
        headerTable.columnModel.getColumn(1).preferredWidth = 170
        headerTable.columnModel.getColumn(2).preferredWidth = 380
        headerTable.putClientProperty("terminateEditOnFocusLost", true)

        val scroll = JScrollPane(headerTable)
        scroll.preferredSize = Dimension(640, 120)

        val add = JButton("Add")
        val remove = JButton("Remove")
        add.addActionListener { headerModel.addRow(arrayOf(true, "", "")) }
        remove.addActionListener {
            val row = headerTable.selectedRow
            if (row >= 0) {
                if (headerTable.isEditing) headerTable.cellEditor?.stopCellEditing()
                headerModel.removeRow(row)
            }
        }

        val buttons = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        buttons.add(add)
        buttons.add(remove)
        buttons.add(JLabel("values are sent verbatim, no escaping or comma splitting"))

        panel.add(scroll, BorderLayout.CENTER)
        panel.add(buttons, BorderLayout.SOUTH)
        return panel
    }

    private fun optionsPanel(): JPanel {
        val panel = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        panel.border = BorderFactory.createTitledBorder("Options")
        panel.add(initializedCheck)
        return panel
    }

    // -------------------------------------------------------------- behaviour

    private fun syncAuthFields() {
        val kind = authBox.selectedIndex
        val bearer = kind == 1
        val basic = kind == 2

        bearerLabel.isVisible = bearer
        bearerField.isVisible = bearer
        basicUserLabel.isVisible = basic
        basicUserField.isVisible = basic
        basicPasswordLabel.isVisible = basic
        basicPasswordField.isVisible = basic

        revalidate()
        repaint()
    }

    private fun onConnect() {
        // A cell still in edit mode has not written back to the model yet, so a
        // header typed and then clicked straight past would silently vanish.
        if (headerTable.isEditing) headerTable.cellEditor?.stopCellEditing()

        val url = urlField.text.trim()
        if (url.isEmpty()) return fail("Enter a URL")
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return fail("URL must start with http:// or https://")
        }

        val timeout = timeoutField.text.trim().toLongOrNull()
        if (timeout == null || timeout <= 0) return fail("Timeout must be a positive number")

        val protocol = protocolField.text.trim().ifEmpty { PREFERRED_PROTOCOL }

        val headers = mutableListOf<HeaderEntry>()
        for (row in 0 until headerModel.rowCount) {
            val enabled = headerModel.getValueAt(row, 0) as? Boolean ?: true
            val name = (headerModel.getValueAt(row, 1) as? String ?: "").trim()
            val value = headerModel.getValueAt(row, 2) as? String ?: ""
            if (name.isEmpty() && value.isBlank()) continue
            headers.add(HeaderEntry(name, value, enabled))
        }

        result = ConnectionConfig(
            name = configName,
            url = url,
            transport = when (transportBox.selectedIndex) {
                1 -> TransportKind.STREAMABLE_HTTP
                2 -> TransportKind.SSE
                else -> TransportKind.AUTO
            },
            timeoutSeconds = timeout,
            protocolVersion = protocol,
            authKind = when (authBox.selectedIndex) {
                1 -> AuthKind.BEARER
                2 -> AuthKind.BASIC
                else -> AuthKind.NONE
            },
            bearerToken = bearerField.text,
            basicUser = basicUserField.text,
            basicPassword = String(basicPasswordField.password),
            headers = headers,
            sendInitializedNotification = initializedCheck.isSelected,
        )
        dispose()
    }

    private fun fail(message: String) {
        errorLabel.text = message
    }
}
