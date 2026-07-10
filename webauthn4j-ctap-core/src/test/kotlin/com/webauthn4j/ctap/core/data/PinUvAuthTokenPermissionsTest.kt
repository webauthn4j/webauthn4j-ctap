package com.webauthn4j.ctap.core.data

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import tools.jackson.databind.json.JsonMapper
import tools.jackson.dataformat.cbor.CBORMapper
import tools.jackson.module.kotlin.KotlinModule

internal class PinUvAuthTokenPermissionsTest {

    private val cborMapper: CBORMapper

    init {
        val jsonMapper = JsonMapper()
        val ctapCborMapper = CBORMapper.builder()
            .addModule(CtapCBORModule())
            .addModule(KotlinModule.Builder().build())
            .build()
        cborMapper = ObjectConverter(jsonMapper, ctapCborMapper).cborMapper
    }

    @Test
    fun cbor_roundtrip_single_permission() {
        val original = PinUvAuthTokenPermissions(PinUvAuthTokenPermission.MC)
        val bytes = cborMapper.writeValueAsBytes(original)
        val deserialized = cborMapper.readValue(bytes, PinUvAuthTokenPermissions::class.java)
        assertThat(deserialized).containsExactlyInAnyOrderElementsOf(original)
        assertThat(deserialized.toBitfield()).isEqualTo(original.toBitfield())
    }

    @Test
    fun cbor_roundtrip_multiple_permissions() {
        val original = PinUvAuthTokenPermissions(PinUvAuthTokenPermission.MC, PinUvAuthTokenPermission.GA)
        val bytes = cborMapper.writeValueAsBytes(original)
        val deserialized = cborMapper.readValue(bytes, PinUvAuthTokenPermissions::class.java)
        assertThat(deserialized).containsExactlyInAnyOrderElementsOf(original)
        assertThat(deserialized.toBitfield()).isEqualTo(0x03)
    }

    @Test
    fun cbor_roundtrip_all_permissions() {
        val original = PinUvAuthTokenPermissions(
            PinUvAuthTokenPermission.MC, PinUvAuthTokenPermission.GA,
            PinUvAuthTokenPermission.CM, PinUvAuthTokenPermission.BE,
            PinUvAuthTokenPermission.LBW, PinUvAuthTokenPermission.ACFG
        )
        val bytes = cborMapper.writeValueAsBytes(original)
        val deserialized = cborMapper.readValue(bytes, PinUvAuthTokenPermissions::class.java)
        assertThat(deserialized).containsExactlyInAnyOrderElementsOf(original)
        assertThat(deserialized.toBitfield()).isEqualTo(0x3F)
    }

    @Test
    fun cbor_deserialize_from_integer() {
        // Simulate CBOR integer 0x03 (MC | GA) as sent by a CTAP client
        val bytes = cborMapper.writeValueAsBytes(0x03)
        val deserialized = cborMapper.readValue(bytes, PinUvAuthTokenPermissions::class.java)
        assertThat(deserialized).containsExactlyInAnyOrder(PinUvAuthTokenPermission.MC, PinUvAuthTokenPermission.GA)
    }

    @Test
    fun toBitfield_and_constructor_consistency() {
        val permissions = PinUvAuthTokenPermissions(PinUvAuthTokenPermission.GA, PinUvAuthTokenPermission.LBW)
        val bitfield = permissions.toBitfield()
        assertThat(bitfield).isEqualTo(0x12)
        val fromBitfield = PinUvAuthTokenPermissions.fromBitfield(bitfield)
        assertThat(fromBitfield).containsExactlyInAnyOrderElementsOf(permissions)
    }
}
