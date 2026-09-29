package com.webauthn4j.ctap.authenticator.transport.usbip

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.DeviceInfo
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.USBSpeed

/** A virtual FIDO2 USB device. Add devices to [USBIPServer] to share one TCP listener. */
class USBIPDevice(
    internal val ctapAuthenticator: CtapAuthenticator,
    val config: USBIPDeviceConfig = USBIPDeviceConfig()
) {
    internal val deviceInfo = DeviceInfo(
        path = "/sys/devices/virtual/usbip/${config.busId}",
        busid = config.busId,
        busnum = config.busNum,
        devnum = config.devNum,
        speed = USBSpeed.FULL,
        idVendor = config.vendorId,
        idProduct = config.productId,
        bcdDevice = config.version,
        bDeviceClass = 0,
        bDeviceSubClass = 0,
        bDeviceProtocol = 0,
        bConfigurationValue = 1,
        bNumConfigurations = 1,
        bNumInterfaces = 1,
        interfaces = listOf(DeviceInfo.InterfaceInfo(0x03, 0x00, 0x00)),
    )

}
