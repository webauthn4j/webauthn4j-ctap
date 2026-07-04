package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData

class AuthenticatorGetInfoResponseDataOptionsSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorGetInfoResponseData.Options>(
        AuthenticatorGetInfoResponseData.Options::class.java,
        listOf(
            FieldSerializationRule("rk") { it.rk?.value },
            FieldSerializationRule("up") { it.up?.value },
            FieldSerializationRule("uv") { it.uv?.value },
            FieldSerializationRule("plat") { it.plat?.value },
            FieldSerializationRule("clientPin") { it.clientPin?.value },
            FieldSerializationRule("pinUvAuthToken") { it.pinUvAuthToken?.value },
            FieldSerializationRule("noMcGaPermissionsWithClientPin") { it.noMcGaPermissionsWithClientPin?.value },
            FieldSerializationRule("largeBlobs") { it.largeBlobs?.value },
            FieldSerializationRule("ep") { it.ep?.value },
            FieldSerializationRule("bioEnroll") { it.bioEnroll?.value },
            FieldSerializationRule("userVerificationMgmtPreview") { it.userVerificationMgmtPreview?.value },
            FieldSerializationRule("uvBioEnroll") { it.uvBioEnroll?.value },
            FieldSerializationRule("authnrCfg") { it.authnrCfg?.value },
            FieldSerializationRule("uvAcfg") { it.uvAcfg?.value },
            FieldSerializationRule("credMgmt") { it.credMgmt?.value },
            FieldSerializationRule("perCredMgmtRO") { it.perCredMgmtRO?.value },
            FieldSerializationRule("credentialMgmtPreview") { it.credentialMgmtPreview?.value },
            FieldSerializationRule("setMinPINLength") { it.setMinPINLength?.value },
            FieldSerializationRule("makeCredUvNotRqd") { it.makeCredUvNotRqd?.value },
            FieldSerializationRule("alwaysUv") { it.alwaysUv?.value }
        ))
