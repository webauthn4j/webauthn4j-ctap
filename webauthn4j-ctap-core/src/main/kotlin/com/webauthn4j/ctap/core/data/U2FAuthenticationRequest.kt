package com.webauthn4j.ctap.core.data

import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.util.ArrayUtil
import java.nio.ByteBuffer

class U2FAuthenticationRequest : AuthenticatorRequest {

    companion object {
        fun createFromCommandAPDU(command: CommandAPDU): U2FAuthenticationRequest {
            val dataIn = command.dataIn
            requireNotNull(dataIn) { "command.dataIn must not be null" }
            require(dataIn.size >= 65) { "command.dataIn must be at least 65 bytes length." }

            val controlByte = command.p1
            val challengeParameter: ByteArray = dataIn.copyOfRange(0, 32)
            val applicationParameter: ByteArray = dataIn.copyOfRange(32, 64)
            val keyHandleLength = dataIn[64].toUByte().toInt()
            val keyHandle = dataIn.copyOfRange(65, 65 + keyHandleLength)
            return U2FAuthenticationRequest(
                controlByte,
                challengeParameter,
                applicationParameter,
                keyHandle
            )
        }
    }

    @Suppress("JoinDeclarationAndAssignment")
    val controlByte: Byte
    val challengeParameter: ByteArray
        get() = ArrayUtil.clone(field)
    val applicationParameter: ByteArray
        get() = ArrayUtil.clone(field)
    val keyHandle: ByteArray
        get() = ArrayUtil.clone(field)

    constructor(
        controlByte: Byte,
        challengeParameter: ByteArray,
        applicationParameter: ByteArray,
        keyHandle: ByteArray
    ) {
        this.controlByte = controlByte
        this.challengeParameter = ArrayUtil.clone(challengeParameter)
        this.applicationParameter = ArrayUtil.clone(applicationParameter)
        this.keyHandle = ArrayUtil.clone(keyHandle)
    }

    fun toBytes(): ByteArray {
        val length = 1 + 32 + 32 + 1 + keyHandle.size
        val keyHandleLength = keyHandle.size.toByte()
        return ByteBuffer.allocate(length)
            .put(controlByte)
            .put(challengeParameter)
            .put(applicationParameter)
            .put(keyHandleLength)
            .put(keyHandle)
            .array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is U2FAuthenticationRequest) return false

        if (controlByte != other.controlByte) return false
        if (!challengeParameter.contentEquals(other.challengeParameter)) return false
        if (!applicationParameter.contentEquals(other.applicationParameter)) return false
        if (!keyHandle.contentEquals(other.keyHandle)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = controlByte.hashCode()
        result = 31 * result + challengeParameter.contentHashCode()
        result = 31 * result + applicationParameter.contentHashCode()
        result = 31 * result + keyHandle.contentHashCode()
        return result
    }


}