package com.webauthn4j.ctap.core.converter

import com.webauthn4j.ctap.core.data.hid.HIDChannelId
import com.webauthn4j.ctap.core.data.hid.HIDCommand
import com.webauthn4j.ctap.core.data.hid.HIDCommand.Companion.CMD_BIT
import com.webauthn4j.ctap.core.data.hid.HIDContinuationPacket
import com.webauthn4j.ctap.core.data.hid.HIDInitializationPacket
import com.webauthn4j.ctap.core.data.hid.HIDPacket
import java.nio.ByteBuffer
import kotlin.experimental.and
import kotlin.experimental.inv

class HIDPacketConverter {


    fun convert(source: ByteArray): HIDPacket {
//        require(source.size == MAX_PACKET_SIZE) { "source must be %d bytes".format(MAX_PACKET_SIZE) }
        val cid = HIDChannelId(source.copyOfRange(0, 4))
        val cmdOrSec = source[4]
        return if ((cmdOrSec and CMD_BIT) == CMD_BIT) {
            val length = ByteBuffer.wrap(byteArrayOf(source[5], source[6])).short.toUShort()
            val data = source.copyOfRange(7, source.size)
            val cmd = cmdOrSec and (CMD_BIT.inv())
            HIDInitializationPacket(cid, HIDCommand(cmd), length, data)
        } else {
            val data = source.copyOfRange(5, source.size)
            HIDContinuationPacket(cid, cmdOrSec, data)
        }
    }

    fun convert(source: HIDPacket): ByteArray {
        return source.toBytes()
    }
}