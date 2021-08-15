package com.webauthn4j.ctap.core.data

import com.webauthn4j.util.ArrayUtil
import java.nio.ByteBuffer

class U2FAuthenticationResponse : AuthenticatorResponse {

    val userPresenceByte: Byte
    val counter: UInt
    val signature: ByteArray
        get() = ArrayUtil.clone(field)

    constructor(userPresenceByte: Byte, counter: UInt, signature: ByteArray) {
        this.userPresenceByte = userPresenceByte
        this.counter = counter
        this.signature = ArrayUtil.clone(signature)
    }

    constructor(userPresence: Boolean, counter: UInt, signature: ByteArray) {
        if(userPresence){
            this.userPresenceByte = 1
        }
        else{
            this.userPresenceByte = 0
        }
        this.counter = counter
        this.signature = ArrayUtil.clone(signature)
    }

    fun toBytes(): ByteArray {
        val length = 1 + 4 + signature.size
        return ByteBuffer.allocate(length).put(userPresenceByte).putInt(counter.toInt()).put(signature).array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is U2FAuthenticationResponse) return false

        if (userPresenceByte != other.userPresenceByte) return false
        if (counter != other.counter) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = userPresenceByte.hashCode()
        result = 31 * result + counter.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }


}