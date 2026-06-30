package com.webauthn4j.unifidokey.usbip

import com.fasterxml.jackson.annotation.JsonInclude
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.attestation.DemoAttestationConstants
import com.webauthn4j.ctap.authenticator.attestation.PackedBasicAttestationStatementProvider
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData
import com.webauthn4j.ctap.core.data.options.ClientPINOption
import com.webauthn4j.ctap.core.data.options.PlatformOption
import com.webauthn4j.ctap.core.data.options.ResidentKeyOption
import com.webauthn4j.ctap.core.data.options.UserPresenceOption
import com.webauthn4j.ctap.core.data.options.UserVerificationOption
import com.webauthn4j.data.AttachmentHint
import com.webauthn4j.data.AuthenticationAlgorithm
import com.webauthn4j.data.AuthenticatorAttestationType
import com.webauthn4j.data.KeyProtectionType
import com.webauthn4j.data.MatcherProtectionType
import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.data.PublicKeyRepresentationFormat
import com.webauthn4j.data.UserVerificationMethod
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.metadata.converter.jackson.WebAuthnMetadataJSONModule
import com.webauthn4j.metadata.data.statement.AuthenticatorGetInfo
import com.webauthn4j.metadata.data.statement.AuthenticatorGetInfo.Options
import com.webauthn4j.metadata.data.statement.MetadataStatement
import com.webauthn4j.metadata.data.statement.VerificationMethodANDCombinations
import com.webauthn4j.metadata.data.statement.VerificationMethodDescriptor
import com.webauthn4j.metadata.data.statement.Version
import com.webauthn4j.util.HexUtil
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import tools.jackson.core.JsonGenerator
import tools.jackson.databind.SerializationFeature
import tools.jackson.databind.SerializationContext
import tools.jackson.databind.annotation.JsonSerialize
import tools.jackson.databind.ser.std.StdSerializer
import java.io.File

@Command(name = "generate-metadata", mixinStandardHelpOptions = true,
    description = ["Generate FIDO MetadataStatement JSON for Conformance Tools"])
class GenerateMetadataStatement : Runnable {

    private val logger = LoggerFactory.getLogger(GenerateMetadataStatement::class.java)

    @Parameters(index = "0", description = ["Output file path for the metadata JSON"])
    lateinit var outputFile: File

    override fun run() {
        val authenticator = CtapAuthenticator(
            attestationStatementProvider = PackedBasicAttestationStatementProvider.createWithDemoAttestationKey(),
            userVerificationHandler = ConsoleUserVerificationHandler()
        )
        val session = authenticator.createSession()
        val getInfoResponse = runBlocking { session.getInfo() }
        val getInfo = getInfoResponse.responseData!!

        val metadataGetInfo = toMetadataGetInfo(getInfo)

        val metadataStatement = MetadataStatement(
            null, // legalHeader
            null, // aaid
            getInfo.aaguid,
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
                )),
                VerificationMethodANDCombinations(listOf(
                    VerificationMethodDescriptor(UserVerificationMethod.PASSCODE_EXTERNAL, null, null, null),
                ))
            ),
            listOf(KeyProtectionType.SOFTWARE), // keyProtection
            null, // isKeyRestricted
            null, // isFreshUserVerificationRequired
            listOf(MatcherProtectionType.ON_CHIP), // matcherProtection
            null, // cryptoStrength
            listOf(AttachmentHint.EXTERNAL, AttachmentHint.WIRED), // attachmentHint
            emptyList(), // tcDisplay
            null, // tcDisplayContentType
            null, // tcDisplayPNGCharacteristics
            listOf(DemoAttestationConstants.DEMO_ROOT_CA_CERTIFICATE), // attestationRootCertificates
            null, // ecdaaTrustAnchors
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==", // icon (1x1 transparent PNG)
            null, // supportedExtensions
            metadataGetInfo
        )

        val objectConverter = ObjectConverter()
        val mapper = objectConverter.jsonMapper.rebuild()
            .addModule(WebAuthnMetadataJSONModule())
            .enable(SerializationFeature.INDENT_OUTPUT)
            .changeDefaultPropertyInclusion { JsonInclude.Value.construct(JsonInclude.Include.NON_NULL, JsonInclude.Include.NON_NULL) }
            .addMixIn(AuthenticatorGetInfo::class.java, AuthenticatorGetInfoHexAaguidMixIn::class.java)
            .build()
        outputFile.writeText(mapper.writeValueAsString(metadataStatement))
        logger.info("Metadata written to {}", outputFile.absolutePath)
    }

    abstract class AuthenticatorGetInfoHexAaguidMixIn {
        @get:JsonSerialize(using = HexAaguidSerializer::class)
        abstract val aaguid: AAGUID
    }

    class HexAaguidSerializer : StdSerializer<AAGUID>(AAGUID::class.java) {
        override fun serialize(value: AAGUID, gen: JsonGenerator, ctxt: SerializationContext) {
            gen.writeString(HexUtil.encodeToString(value.bytes).lowercase())
        }
    }

    companion object {
        private fun toMetadataGetInfo(getInfo: AuthenticatorGetInfoResponseData): AuthenticatorGetInfo {
            return AuthenticatorGetInfo(
                getInfo.versions,
                getInfo.extensions ?: emptyList(),
                getInfo.aaguid,
                getInfo.options?.let { toMetadataOptions(it) },
                getInfo.maxMsgSize?.toInt(),
                getInfo.pinProtocols?.map { PinProtocolVersion.create(it.value.toInt()) }
            )
        }

        private fun toMetadataOptions(options: AuthenticatorGetInfoResponseData.Options): Options {
            return Options(
                when (options.plat) {
                    PlatformOption.PLATFORM -> Options.PlatformOption.PLATFORM
                    else -> Options.PlatformOption.CROSS_PLATFORM
                },
                when (options.rk) {
                    ResidentKeyOption.SUPPORTED -> Options.ResidentKeyOption.SUPPORTED
                    else -> Options.ResidentKeyOption.NOT_SUPPORTED
                },
                when (options.clientPin) {
                    ClientPINOption.SET -> Options.ClientPINOption.SET
                    ClientPINOption.NOT_SET -> Options.ClientPINOption.NOT_SET
                    else -> null
                },
                when (options.up) {
                    UserPresenceOption.SUPPORTED -> Options.UserPresenceOption.SUPPORTED
                    else -> Options.UserPresenceOption.NOT_SUPPORTED
                },
                when (options.uv) {
                    UserVerificationOption.READY -> Options.UserVerificationOption.READY
                    UserVerificationOption.NOT_READY -> Options.UserVerificationOption.NOT_READY
                    else -> null
                },
                null,
                null
            )
        }
    }
}
