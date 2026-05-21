package com.webauthn4j.unifidokey.usbip

import com.fasterxml.jackson.annotation.JsonInclude
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.attestation.DemoAttestationConstants
import com.webauthn4j.data.AttachmentHint
import com.webauthn4j.data.AuthenticationAlgorithm
import com.webauthn4j.data.AuthenticatorAttestationType
import com.webauthn4j.data.KeyProtectionType
import com.webauthn4j.data.MatcherProtectionType
import com.webauthn4j.data.PublicKeyRepresentationFormat
import com.webauthn4j.data.UserVerificationMethod
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule
import com.webauthn4j.metadata.data.statement.AuthenticatorGetInfo
import com.webauthn4j.metadata.data.statement.AuthenticatorGetInfo.Options
import com.webauthn4j.metadata.data.statement.MetadataStatement
import com.webauthn4j.metadata.data.statement.VerificationMethodANDCombinations
import com.webauthn4j.metadata.data.statement.VerificationMethodDescriptor
import com.webauthn4j.metadata.data.statement.Version
import picocli.CommandLine.Command
import tools.jackson.databind.SerializationFeature

@Command(name = "generate-metadata", mixinStandardHelpOptions = true,
    description = ["Generate FIDO MetadataStatement JSON for Conformance Tools"])
class GenerateMetadataStatement : Runnable {

    override fun run() {
        val aaguid = CtapAuthenticator.AAGUID

        val metadataStatement = MetadataStatement(
            null, // legalHeader
            null, // aaid
            aaguid,
            null, // attestationCertificateKeyIdentifiers
            "UniFIDOKey USB-IP Virtual FIDO2 Authenticator", // description
            null, // alternativeDescriptions
            2,    // authenticatorVersion
            "fido2", // protocolFamily
            3,    // schema
            listOf(Version(1, 0)), // upv
            listOf(AuthenticationAlgorithm.SECP256R1_ECDSA_SHA256_RAW), // authenticationAlgorithms
            listOf(PublicKeyRepresentationFormat.COSE), // publicKeyAlgAndEncodings
            listOf(AuthenticatorAttestationType.BASIC_FULL), // attestationTypes
            listOf( // userVerificationDetails
                VerificationMethodANDCombinations(listOf(
                    VerificationMethodDescriptor(UserVerificationMethod.PRESENCE_INTERNAL, null, null, null),
                )),
                VerificationMethodANDCombinations(listOf(
                    VerificationMethodDescriptor(UserVerificationMethod.PASSCODE_INTERNAL, null, null, null),
                ))
            ),
            listOf(KeyProtectionType.SOFTWARE), // keyProtection
            null, // isKeyRestricted
            null, // isFreshUserVerificationRequired
            listOf(MatcherProtectionType.ON_CHIP), // matcherProtection
            null, // cryptoStrength
            listOf(AttachmentHint.EXTERNAL), // attachmentHint
            emptyList(), // tcDisplay
            null, // tcDisplayContentType
            null, // tcDisplayPNGCharacteristics
            listOf(DemoAttestationConstants.DEMO_ROOT_CA_CERTIFICATE), // attestationRootCertificates
            null, // ecdaaTrustAnchors
            null, // icon
            null, // supportedExtensions
            AuthenticatorGetInfo(
                listOf("U2F_V2", "FIDO_2_0"),
                null, // extensions
                aaguid,
                Options(
                    Options.PlatformOption.CROSS_PLATFORM,
                    Options.ResidentKeyOption.SUPPORTED,
                    null, // clientPin
                    Options.UserPresenceOption.SUPPORTED,
                    Options.UserVerificationOption.READY,
                    null, // uvToken
                    null  // config
                ),
                2048, // maxMsgSize
                null  // pinUvAuthProtocols
            )
        )

        val objectConverter = ObjectConverter()
        val mapper = objectConverter.jsonMapper.rebuild()
            .addModule(WebAuthnMetadataJSONModule())
            .enable(SerializationFeature.INDENT_OUTPUT)
            .changeDefaultPropertyInclusion { JsonInclude.Value.construct(JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL) }
            .build()
        println(mapper.writeValueAsString(metadataStatement))
    }
}
