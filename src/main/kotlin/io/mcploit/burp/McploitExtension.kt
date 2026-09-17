package io.mcploit.burp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import io.mcploit.burp.ui.McpClientTab

class McploitExtension : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("MCPloit Client")

        val tab = McpClientTab(api)
        api.userInterface().registerSuiteTab("MCPloit", tab.component)

        api.extension().registerUnloadingHandler {
            tab.shutdown()
            api.logging().logToOutput("MCPloit Client unloaded")
        }

        api.logging().logToOutput(
            "MCPloit Client loaded. Open the MCPloit tab, enter a server URL and connect."
        )
    }
}
