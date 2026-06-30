package com.webauthn4j.ctap.authenticator.transport.uhid

import com.webauthn4j.ctap.authenticator.transport.uhid.event.CreateDeviceEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.DestroyDeviceEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.InputReportEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.OutputReportEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.StartEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.UHIDEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.UnknownEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.FidoHIDReportDescriptor
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal class UHIDEventTest {

    @Test
    fun createDeviceEvent_setsTypeAndFields() {
        val config = UHIDDeviceConfig(
            deviceName = "TestDevice",
            vendorId = 0x0525,
            productId = 0xF025,
            version = 0x0100,
            physicalAddress = "phys",
            uniqueId = "uniq"
        )
        val rdesc = FidoHIDReportDescriptor.DESCRIPTOR

        val event = CreateDeviceEvent(config, rdesc).toBytes()

        assertThat(event.size).isEqualTo(UHIDEvent.EVENT_SIZE)

        val buf = ByteBuffer.wrap(event).order(ByteOrder.LITTLE_ENDIAN)

        // type = UHID_CREATE2 (11)
        assertThat(buf.getInt(0)).isEqualTo(11)

        // name
        val nameBytes = ByteArray(128)
        buf.position(4)
        buf.get(nameBytes)
        val name = String(nameBytes, Charsets.UTF_8).trimEnd('\u0000')
        assertThat(name).isEqualTo("TestDevice")

        // phys
        val physBytes = ByteArray(64)
        buf.position(132)
        buf.get(physBytes)
        val phys = String(physBytes, Charsets.UTF_8).trimEnd('\u0000')
        assertThat(phys).isEqualTo("phys")

        // uniq
        val uniqBytes = ByteArray(64)
        buf.position(196)
        buf.get(uniqBytes)
        val uniq = String(uniqBytes, Charsets.UTF_8).trimEnd('\u0000')
        assertThat(uniq).isEqualTo("uniq")

        // rd_size
        val rdSize = buf.getShort(260).toInt() and 0xFFFF
        assertThat(rdSize).isEqualTo(rdesc.size)

        // bus
        assertThat(buf.getShort(262)).isEqualTo(0x03.toShort()) // BUS_USB

        // vendor, product, version
        assertThat(buf.getInt(264)).isEqualTo(0x0525)
        assertThat(buf.getInt(268)).isEqualTo(0xF025)
        assertThat(buf.getInt(272)).isEqualTo(0x0100)

        // country
        assertThat(buf.getInt(276)).isEqualTo(0)

        // rd_data
        val rdData = ByteArray(rdesc.size)
        buf.position(280)
        buf.get(rdData)
        assertThat(rdData).isEqualTo(rdesc)
    }

    @Test
    fun inputReportEvent_setsTypeAndData() {
        val data = ByteArray(64) { it.toByte() }
        val event = InputReportEvent(data).toBytes()

        assertThat(event.size).isEqualTo(UHIDEvent.EVENT_SIZE)

        val buf = ByteBuffer.wrap(event).order(ByteOrder.LITTLE_ENDIAN)
        // type = UHID_INPUT2 (12)
        assertThat(buf.getInt(0)).isEqualTo(12)
        assertThat(buf.getShort(4).toInt() and 0xFFFF).isEqualTo(64)

        val readData = ByteArray(64)
        buf.position(6)
        buf.get(readData)
        assertThat(readData).isEqualTo(data)
    }

    @Test
    fun destroyDeviceEvent_setsType() {
        val event = DestroyDeviceEvent.toBytes()

        assertThat(event.size).isEqualTo(UHIDEvent.EVENT_SIZE)

        val buf = ByteBuffer.wrap(event).order(ByteOrder.LITTLE_ENDIAN)
        // type = UHID_DESTROY (1)
        assertThat(buf.getInt(0)).isEqualTo(1)
    }

    @Test
    fun parse_returnsOutputReportEvent() {
        val reportData = ByteArray(64) { (it + 0x10).toByte() }
        val eventBytes = ByteBuffer.allocate(UHIDEvent.EVENT_SIZE)
            .order(ByteOrder.LITTLE_ENDIAN)
            .apply {
                putInt(6) // UHID_OUTPUT
                position(4)
                put(reportData)
                position(4100)
                putShort(64)
                put(0x00)
            }
            .array()

        val event = UHIDEvent.parse(eventBytes)

        assertThat(event).isInstanceOf(OutputReportEvent::class.java)
        val output = event as OutputReportEvent
        assertThat(output.size).isEqualTo(64)
        assertThat(output.data).isEqualTo(reportData)
        assertThat(output.rtype).isEqualTo(0x00.toByte())
    }

    @Test
    fun parse_returnsStartEvent() {
        val eventBytes = ByteBuffer.allocate(UHIDEvent.EVENT_SIZE)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(2) // UHID_START
            .array()

        assertThat(UHIDEvent.parse(eventBytes)).isEqualTo(StartEvent)
    }

    @Test
    fun parse_returnsUnknownForUnknownType() {
        val eventBytes = ByteBuffer.allocate(UHIDEvent.EVENT_SIZE)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(99)
            .array()

        val event = UHIDEvent.parse(eventBytes)
        assertThat(event).isInstanceOf(UnknownEvent::class.java)
        assertThat((event as UnknownEvent).type).isEqualTo(99)
    }

    @Test
    fun fidoHIDReportDescriptor_hasExpectedSize() {
        assertThat(FidoHIDReportDescriptor.DESCRIPTOR.size).isEqualTo(34)
    }
}
