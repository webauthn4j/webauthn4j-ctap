package com.webauthn4j.unifidokey.usbip

import io.quarkus.picocli.runtime.annotations.TopCommand
import picocli.CommandLine.Command

@TopCommand
@Command(name = "unifidokey-usbip", mixinStandardHelpOptions = true,
    subcommands = [UniFIDOKeyUSBIP::class, GenerateMetadataStatement::class])
class TopCommand
