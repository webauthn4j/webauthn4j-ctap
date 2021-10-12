package com.unifidokey.app

import com.webauthn4j.converter.exception.DataConversionException
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.util.HexUtil
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.mockito.Mockito.spy

class UnifidoKeyModuleBaseTest {

    private lateinit var objectConverter: ObjectConverter

    @Before
    fun setUp() {
        val unifidoKeyModule = spy(UnifidoKeyModuleBase::class.java)
        objectConverter = unifidoKeyModule.provideObjectConverter()
    }

    @Test
    fun cborConverter_String_test() {
        val data = HexUtil.decode("A1656669656C64F5") // {"field": true}
        try {
            objectConverter.cborConverter.readValue(
                data,
                StringContainerTestDto::class.java
            ) // should fail because field is String type
            fail("should not reach here")
        } catch (e: DataConversionException) {
            //nop
        }

    }

    data class StringContainerTestDto(var field: String)

    @Test
    fun cborConverter_ByteArray_test() {
//        val data = HexUtil.decode("A1656669656C64F5") // {"field": true}
        val data = HexUtil.decode("A1656669656C6460") // {"field": ""}
        try {
            objectConverter.cborConverter.readValue(
                data,
                ByteArrayContainerTestDto::class.java
            ) // should fail because field is String type
            fail("should not reach here")
        } catch (e: DataConversionException) {
            //nop
            e.toString()
        }

    }

    data class ByteArrayContainerTestDto(var field: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ByteArrayContainerTestDto) return false

            if (!field.contentEquals(other.field)) return false

            return true
        }

        override fun hashCode(): Int {
            return field.contentHashCode()
        }
    }


}