package com.webauthn4j.ctap.core.converter.jackson.deserializer

import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermissions
import tools.jackson.core.JsonParser
import tools.jackson.databind.DeserializationContext
import tools.jackson.databind.deser.std.StdDeserializer

class PinUvAuthTokenPermissionsDeserializer : StdDeserializer<PinUvAuthTokenPermissions>(PinUvAuthTokenPermissions::class.java) {
    override fun deserialize(p: JsonParser, ctxt: DeserializationContext): PinUvAuthTokenPermissions {
        return PinUvAuthTokenPermissions.fromBitfield(p.intValue)
    }
}
