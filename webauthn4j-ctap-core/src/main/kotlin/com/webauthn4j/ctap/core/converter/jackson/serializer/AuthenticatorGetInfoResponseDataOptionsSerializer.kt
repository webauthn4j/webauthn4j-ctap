package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData

// CTAP2 canonical CBOR: string keys sorted by length first, then lexicographic
class AuthenticatorGetInfoResponseDataOptionsSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorGetInfoResponseData.Options>(
        AuthenticatorGetInfoResponseData.Options::class.java,
        listOf(
            FieldSerializationRule("ep") { it.ep?.value },
            FieldSerializationRule("rk") { it.rk?.value },
            FieldSerializationRule("up") { it.up?.value },
            FieldSerializationRule("uv") { it.uv?.value },
            FieldSerializationRule("plat") { it.plat?.value },
            FieldSerializationRule("uvAcfg") { it.uvAcfg?.value },
            FieldSerializationRule("alwaysUv") { it.alwaysUv?.value },
            FieldSerializationRule("credMgmt") { it.credMgmt?.value },
            FieldSerializationRule("authnrCfg") { it.authnrCfg?.value },
            FieldSerializationRule("bioEnroll") { it.bioEnroll?.value },
            FieldSerializationRule("clientPin") { it.clientPin?.value },
            FieldSerializationRule("largeBlobs") { it.largeBlobs?.value },
            FieldSerializationRule("uvBioEnroll") { it.uvBioEnroll?.value },
            FieldSerializationRule("perCredMgmtRO") { it.perCredMgmtRO?.value },
            FieldSerializationRule("pinUvAuthToken") { it.pinUvAuthToken?.value },
            FieldSerializationRule("setMinPINLength") { it.setMinPINLength?.value },
            FieldSerializationRule("makeCredUvNotRqd") { it.makeCredUvNotRqd?.value },
            FieldSerializationRule("credentialMgmtPreview") { it.credentialMgmtPreview?.value },
            FieldSerializationRule("userVerificationMgmtPreview") { it.userVerificationMgmtPreview?.value },
            FieldSerializationRule("noMcGaPermissionsWithClientPin") { it.noMcGaPermissionsWithClientPin?.value }
        ))
