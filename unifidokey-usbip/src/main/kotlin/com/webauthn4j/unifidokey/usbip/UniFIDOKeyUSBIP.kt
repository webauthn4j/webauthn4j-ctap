package com.webauthn4j.unifidokey.usbip

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.attestation.PackedBasicAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.data.settings.CredentialSelectorSetting
import com.webauthn4j.ctap.authenticator.extension.CredProtectExtensionProcessor
import com.webauthn4j.ctap.authenticator.transport.usbip.USBIPDevice
import com.webauthn4j.ctap.authenticator.transport.usbip.USBIPDeviceConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.jboss.logging.Logger
import picocli.CommandLine.Command
import picocli.CommandLine.Option

@Command(name = "serve", mixinStandardHelpOptions = true,
    description = ["Start USB-IP server exposing a virtual FIDO2 security key"])
class UniFIDOKeyUSBIP : Runnable {

    @Option(names = ["-H", "--host"], description = ["Bind address (default: 0.0.0.0)"])
    var host: String = "0.0.0.0"

    @Option(names = ["-p", "--port"], description = ["TCP port (default: 3240)"])
    var port: Int = 3240

    private val logger = Logger.getLogger(UniFIDOKeyUSBIP::class.java)

    override fun run() {
        val config = USBIPDeviceConfig(host = host, port = port)
        val authenticator = CtapAuthenticator(
            attestationStatementProvider = PackedBasicAttestationStatementProvider.createWithDemoAttestationKey(),
            userVerificationHandler = ConsoleUserVerificationHandler(),
            extensionProcessors = listOf(CredProtectExtensionProcessor())
        ).apply {
            credentialSelector = CredentialSelectorSetting.CLIENT_PLATFORM
        }
        val device = USBIPDevice(authenticator, config)
        val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())

        Runtime.getRuntime().addShutdownHook(Thread {
            runBlocking { device.stop() }
        })

        runBlocking {
            device.start(scope)
        }

        logger.info("USB-IP Virtual FIDO2 Device is running")
        logger.infof("  Server: %s:%d", config.host, config.port)
        logger.infof("  Bus ID: %s", config.busId)

        // Keep running until interrupted
        Thread.currentThread().join()
    }
}
