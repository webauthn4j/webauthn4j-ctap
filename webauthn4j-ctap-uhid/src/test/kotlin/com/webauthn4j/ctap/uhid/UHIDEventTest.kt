package com.webauthn4j.ctap.uhid

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

internal class UHIDEventTest {

    @Test
    fun createCreate2_setsTypeAndFields() {
        val config = UHIDDeviceConfig(
            deviceName = "TestDevice",
            vendorId = 0x0525,
            productId = 0xF025,
            version = 0x0100,
            physicalAddress = "phys",
            uniqueId = "uniq"
        )
        val rdesc = FidoHIDReportDescriptor.DESCRIPTOR

        val event = UHIDEvent.createCreate2(config, rdesc)

        assertThat(event.size).isEqualTo(UHIDEvent.EVENT_SIZE)

        val buf = ByteBuffer.wrap(event).order(ByteOrder.LITTLE_ENDIAN)

        // type
        assertThat(buf.getInt(0)).isEqualTo(UHIDEventType.UHID_CREATE2.value)

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

        // rd_data (at the end)
        val rdData = ByteArray(rdesc.size)
        buf.position(280)
        buf.get(rdData)
        assertThat(rdData).isEqualTo(rdesc)
    }

    @Test
    fun createInput2_setsTypeAndData() {
        val data = ByteArray(64) { it.toByte() }
        val event = UHIDEvent.createInput2(data)

        assertThat(event.size).isEqualTo(UHIDEvent.EVENT_SIZE)

        val buf = ByteBuffer.wrap(event).order(ByteOrder.LITTLE_ENDIAN)
        assertThat(buf.getInt(0)).isEqualTo(UHIDEventType.UHID_INPUT2.value)
        assertThat(buf.getShort(4).toInt() and 0xFFFF).isEqualTo(64)

        val readData = ByteArray(64)
        buf.position(6)
        buf.get(readData)
        assertThat(readData).isEqualTo(data)
    }

    @Test
    fun createDestroy_setsType() {
        val event = UHIDEvent.createDestroy()

        assertThat(event.size).isEqualTo(UHIDEvent.EVENT_SIZE)

        val buf = ByteBuffer.wrap(event).order(ByteOrder.LITTLE_ENDIAN)
        assertThat(buf.getInt(0)).isEqualTo(UHIDEventType.UHID_DESTROY.value)
    }

    @Test
    fun parseType_returnsCorrectType() {
        val event = ByteBuffer.allocate(UHIDEvent.EVENT_SIZE)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(UHIDEventType.UHID_OUTPUT.value)
            .array()

        assertThat(UHIDEvent.parseType(event)).isEqualTo(UHIDEventType.UHID_OUTPUT)
    }

    @Test
    fun parseType_returnsNullForUnknownType() {
        val event = ByteBuffer.allocate(UHIDEvent.EVENT_SIZE)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putInt(99)
            .array()

        assertThat(UHIDEvent.parseType(event)).isNull()
    }

    @Test
    fun parseOutput_extractsDataCorrectly() {
        val reportData = ByteArray(64) { (it + 0x10).toByte() }
        val event = ByteBuffer.allocate(UHIDEvent.EVENT_SIZE)
            .order(ByteOrder.LITTLE_ENDIAN)
            .apply {
                putInt(UHIDEventType.UHID_OUTPUT.value)
                position(4)
                put(reportData) // data[4096] at offset 4
                position(4100)
                putShort(64) // size at offset 4100
                put(0x00) // rtype at offset 4102
            }
            .array()

        val output = UHIDEvent.parseOutput(event)

        assertThat(output.size).isEqualTo(64)
        assertThat(output.data).isEqualTo(reportData)
        assertThat(output.rtype).isEqualTo(0x00.toByte())
    }

    @Test
    fun fidoHIDReportDescriptor_hasExpectedSize() {
        assertThat(FidoHIDReportDescriptor.DESCRIPTOR.size).isEqualTo(34)
    }
}
