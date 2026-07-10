package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermissions
import tools.jackson.core.JsonGenerator
import tools.jackson.databind.SerializationContext
import tools.jackson.databind.ser.std.StdSerializer

class PinUvAuthTokenPermissionsSerializer : StdSerializer<PinUvAuthTokenPermissions>(PinUvAuthTokenPermissions::class.java) {
    override fun serialize(value: PinUvAuthTokenPermissions, gen: JsonGenerator, ctxt: SerializationContext) {
        gen.writeNumber(value.toBitfield())
    }
}
