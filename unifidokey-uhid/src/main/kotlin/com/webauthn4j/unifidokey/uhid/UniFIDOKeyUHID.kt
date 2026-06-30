package com.webauthn4j.unifidokey.uhid

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.uhid.UHIDDevice
import com.webauthn4j.ctap.authenticator.transport.uhid.UHIDDeviceConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.jboss.logging.Logger
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.io.File
import kotlin.system.exitProcess

@Command(name = "unifidokey-uhid", mixinStandardHelpOptions = true,
    description = ["Virtual FIDO2 security key via Linux UHID"])
class UniFIDOKeyUHID : Runnable {

    @Option(names = ["-d", "--device"], description = ["UHID device path (default: /dev/uhid)"])
    var devicePath: String = "/dev/uhid"

    private val logger = Logger.getLogger(UniFIDOKeyUHID::class.java)

    override fun run() {
        checkDeviceAccess()

        val config = UHIDDeviceConfig(devicePath = devicePath)
        val authenticator = CtapAuthenticator()
        val device = UHIDDevice(authenticator, config)
        val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())

        Runtime.getRuntime().addShutdownHook(Thread {
            runBlocking { device.stop() }
        })

        runBlocking {
            device.start(scope)
        }

        logger.info("UHID Virtual FIDO2 Device is running")
        logger.infof("  Device path: %s", config.devicePath)

        // Keep running until interrupted
        Thread.currentThread().join()
    }

    private fun checkDeviceAccess() {
        val uhidFile = File(devicePath)
        if (!uhidFile.exists()) {
            logger.errorf("%s does not exist. Make sure your kernel has UHID support (Linux 3.6+).", devicePath)
            exitProcess(1)
        }
        if (!uhidFile.canRead() || !uhidFile.canWrite()) {
            logger.errorf("No read/write permission on %s. Try running with sudo or configure udev rules.", devicePath)
            exitProcess(1)
        }
    }
}
