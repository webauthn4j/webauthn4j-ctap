package com.webauthn4j.ctap.core.data.nfc

import com.webauthn4j.ctap.core.util.internal.HexUtil
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
        private const val POS_CLA = 0
        private const val POS_INS = 1
        private const val POS_P1 = 2
        private const val POS_P2 = 3
        private const val POS_P2_NEXT = 4
        private const val HEADER_LENGTH = 4

        private const val SHORT_LENGTH_LC_LENGTH = 1
        private const val EXTENDED_LENGTH_LC_LENGTH = 3

        private const val SHORT_LENGTH_LE_LENGTH = 1
        private const val CASE2_EXTENDED_LENGTH_LE_LENGTH = 2
        private const val EXTENDED_LENGTH_LE_LENGTH = 3

        private const val CASE1_APDU_LENGTH = 4
        private const val CASE2_SHORT_APDU_LENGTH = 5
        private const val CASE2_EXTENDED_APDU_LENGTH = 7

        @SuppressWarnings("kotlin:S3776")
        @JvmStatic
        fun parse(apdu: ByteArray): CommandAPDU {

            // APDU format ref. https://smartcardguy.hatenablog.jp/entry/2018/08/11/153334

            AssertUtil.isTrue(apdu.size >= HEADER_LENGTH, "apdu must have sufficient length")
            val cla = apdu[POS_CLA]
            val ins = apdu[POS_INS]
            val p1 = apdu[POS_P1]
            val p2 = apdu[POS_P2]
            val lc: ByteArray?
            val dataIn: ByteArray?
            val le: ByteArray?

            // case1 APDU
            if (apdu.size == CASE1_APDU_LENGTH) {
                lc = null
                dataIn = null
                le = null
            }
            else if (apdu[POS_P2_NEXT] == 0.toByte() && apdu.size != CASE2_SHORT_APDU_LENGTH) {
                // case2 extended APDU
                if (apdu.size == CASE2_EXTENDED_APDU_LENGTH) {
                    val length = apdu.copyOfRange(POS_P2_NEXT, POS_P2_NEXT + CASE2_EXTENDED_LENGTH_LE_LENGTH)
                    lc = null
                    dataIn = null
                    le = length
                } else {
                    val length = apdu.copyOfRange(POS_P2_NEXT, POS_P2_NEXT + EXTENDED_LENGTH_LC_LENGTH)
                    lc = length
                    val dataLength = getLengthFromLengthField(lc)
                    val dataPos = POS_P2_NEXT + EXTENDED_LENGTH_LC_LENGTH
                    dataIn = apdu.copyOfRange(dataPos, dataPos + dataLength)
                    le = when (apdu.size) {
                        // case3 extended APDU
                        dataPos + dataLength -> null
                        // case4
                        else -> apdu.copyOfRange(dataPos + dataLength, apdu.size)
                    }
                }
            } else {
                // case2 short APDU
                if (apdu.size == CASE2_SHORT_APDU_LENGTH) {
                    lc = null
                    dataIn = null
                    le = byteArrayOf(apdu[POS_P2_NEXT])
                } else {
                    lc = byteArrayOf(apdu[POS_P2_NEXT])
                    val dataLength = getLengthFromLengthField(lc)
                    val dataPos = POS_P2_NEXT + SHORT_LENGTH_LC_LENGTH
                    dataIn = apdu.copyOfRange(dataPos, dataPos + dataLength)
                    le = when (apdu.size) {
                        // case3 short APDU
                        dataPos + dataLength -> null
                        // case4
                        else -> apdu.copyOfRange(dataPos + dataLength, apdu.size)
                    }
                }
            }
            return CommandAPDU(cla, ins, p1, p2, lc, dataIn, le)
        }

        private fun getLengthFromLengthField(bytes: ByteArray): Int {
            return when (bytes.size) {
                1 -> {
                    when {
                        bytes.first() == 0.toByte() -> UByte.MAX_VALUE.toInt()
                        else -> UnsignedNumberUtil.getUnsignedByte(bytes.first()).toInt()
                    }
                }
                2, 3 -> {
                    when (val length = UnsignedNumberUtil.getUnsignedShort(bytes.copyOfRange(bytes.size - 2, bytes.size))) {
                        0 -> UShort.MAX_VALUE.toInt()
                        else -> length
                    }
                }
                else -> throw IllegalArgumentException("length field must be 1-3 bytes")
            }
        }
    }

    override fun toString(): String {
        return "CommandAPDU(cla=$cla, ins=$ins, p1=$p1, p2=$p2, lc=${HexUtil.encodeToString(lc)}, dataIn=${HexUtil.encodeToString(dataIn)}, le=${HexUtil.encodeToString(le)})"
    }

    @SuppressWarnings("kotlin:S3776")
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CommandAPDU) return false

        if (cla != other.cla) return false
        if (ins != other.ins) return false
        if (p1 != other.p1) return false
        if (p2 != other.p2) return false
        if (lc != null) {
            if (other.lc == null) return false
            if (!lc.contentEquals(other.lc)) return false
        } else if (other.lc != null) return false
        if (dataIn != null) {
            if (other.dataIn == null) return false
            if (!dataIn.contentEquals(other.dataIn)) return false
        } else if (other.dataIn != null) return false
        if (le != null) {
            if (other.le == null) return false
            if (!le.contentEquals(other.le)) return false
        } else if (other.le != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = cla.toInt()
        result = 31 * result + ins
        result = 31 * result + p1
        result = 31 * result + p2
        result = 31 * result + (lc?.contentHashCode() ?: 0)
        result = 31 * result + (dataIn?.contentHashCode() ?: 0)
        result = 31 * result + (le?.contentHashCode() ?: 0)
        return result
    }


}