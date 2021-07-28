package com.webauthn4j.ctap.core.data.nfc

import com.webauthn4j.util.ArrayUtil
import com.webauthn4j.util.AssertUtil
import com.webauthn4j.util.UnsignedNumberUtil

class CommandAPDU {

    val cla: Byte
    val ins: Byte
    val p1: Byte
    val p2: Byte

    val lc: ByteArray?
        get() = ArrayUtil.clone(field)
    val dataIn: ByteArray?
        get() = ArrayUtil.clone(field)
    val le: ByteArray?
        get() = ArrayUtil.clone(field)

    constructor(cla: Byte, ins: Byte, p1: Byte, p2: Byte) {
        this.cla = cla
        this.ins = ins
        this.p1 = p1
        this.p2 = p2
        lc = null
        dataIn = null
        le = null
    }

    constructor(cla: Byte, ins: Byte, p1: Byte, p2: Byte, le: ByteArray?) {
        this.cla = cla
        this.ins = ins
        this.p1 = p1
        this.p2 = p2
        lc = null
        dataIn = null
        this.le = ArrayUtil.clone(le)
    }

    constructor(cla: Byte, ins: Byte, p1: Byte, p2: Byte, lc: ByteArray?, dataIn: ByteArray?) {
        this.cla = cla
        this.ins = ins
        this.p1 = p1
        this.p2 = p2
        this.lc = ArrayUtil.clone(lc)
        this.dataIn = ArrayUtil.clone(dataIn)
        le = null
    }

    constructor(
        cla: Byte,
        ins: Byte,
        p1: Byte,
        p2: Byte,
        lc: ByteArray?,
        dataIn: ByteArray?,
        le: ByteArray?
    ) {
        this.cla = cla
        this.ins = ins
        this.p1 = p1
        this.p2 = p2
        this.lc = ArrayUtil.clone(lc)
        this.dataIn = ArrayUtil.clone(dataIn)
        this.le = ArrayUtil.clone(le)
    }


    val maxResponseDataSize: Int
        get() {
            val length = le

            return if (length == null || length.isEmpty()) {
                0
            } else {
                getLengthFromLengthField(length)
            }
        }

    companion object {
        private const val CLA_POS = 0
        private const val INS_POS = 1
        private const val P1_POS = 2
        private const val P2_POS = 3
        private const val BYTE_AFTER_P2_POS = 4
        private const val HEADER_LENGTH = 4
        private const val SHORT_LENGTH_LENGTH = 1
        private const val EXTENDED_LENGTH_LENGTH = 3
        private const val CASE1_APDU_LENGTH = 4
        private const val CASE2_SHORT_APDU_LENGTH = 5
        private const val CASE2_EXTENDED_APDU_LENGTH = 7

        @JvmStatic
        fun parse(apdu: ByteArray): CommandAPDU {
            AssertUtil.isTrue(apdu.size >= HEADER_LENGTH, "apdu must have sufficient length")
            val cla = apdu[CLA_POS]
            val ins = apdu[INS_POS]
            val p1 = apdu[P1_POS]
            val p2 = apdu[P2_POS]
            val lc: ByteArray?
            val dataIn: ByteArray?
            val le: ByteArray?

            // case1 APDU
            if (apdu.size == CASE1_APDU_LENGTH) {
                lc = null
                dataIn = null
                le = null
            } else if (apdu[BYTE_AFTER_P2_POS] == 0.toByte() && apdu.size != CASE2_SHORT_APDU_LENGTH) {
                val length =
                    apdu.copyOfRange(BYTE_AFTER_P2_POS, BYTE_AFTER_P2_POS + EXTENDED_LENGTH_LENGTH)
                // case2 extended APDU
                if (apdu.size == CASE2_EXTENDED_APDU_LENGTH) {
                    lc = null
                    dataIn = null
                    le = length
                } else {
                    lc = length
                    val dataLength = getLengthFromLengthField(lc)
                    val dataPos = BYTE_AFTER_P2_POS + EXTENDED_LENGTH_LENGTH
                    dataIn = apdu.copyOfRange(dataPos, dataPos + dataLength)
                    // case3 extended APDU
                    le = if (apdu.size == dataPos + dataLength) {
                        null
                    } else {
                        apdu.copyOfRange(dataPos + dataLength, apdu.size)
                    }
                }
            } else {
                // case2 short APDU
                if (apdu.size == CASE2_SHORT_APDU_LENGTH) {
                    lc = null
                    dataIn = null
                    le = byteArrayOf(apdu[BYTE_AFTER_P2_POS])
                } else {
                    lc = byteArrayOf(apdu[BYTE_AFTER_P2_POS])
                    val dataLength = getLengthFromLengthField(lc)
                    val dataPos = BYTE_AFTER_P2_POS + SHORT_LENGTH_LENGTH
                    dataIn = apdu.copyOfRange(dataPos, dataPos + dataLength)
                    // case3 short APDU
                    le = if (apdu.size == dataPos + dataLength) {
                        null
                    } else {
                        apdu.copyOfRange(dataPos + dataLength, apdu.size)
                    }
                }
            }
            return CommandAPDU(cla, ins, p1, p2, lc, dataIn, le)
        }

        private fun getLengthFromLengthField(length: ByteArray): Int {
            return if (length.size == SHORT_LENGTH_LENGTH) {
                if (length.first() == 0.toByte()) {
                    256
                } else {
                    UnsignedNumberUtil.getUnsignedByte(length[0]).toInt()
                }
            } else {
                UnsignedNumberUtil.getUnsignedShort(length.copyOfRange(1, 3))
            }
        }
    }
}