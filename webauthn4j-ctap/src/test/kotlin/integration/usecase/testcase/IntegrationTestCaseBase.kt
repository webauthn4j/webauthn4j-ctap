package integration.usecase.testcase

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.CredentialSelectionHandler
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSettings
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FBasicAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.PackedBasicAttestationStatementProvider
import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.ctap.authenticator.data.settings.*
import com.webauthn4j.ctap.authenticator.store.AuthenticatorPropertyStore
import com.webauthn4j.ctap.authenticator.store.InMemoryAuthenticatorPropertyStore
import com.webauthn4j.ctap.client.ClientProperty
import com.webauthn4j.ctap.client.CtapAuthenticatorHandle
import com.webauthn4j.ctap.client.CtapClient
import com.webauthn4j.ctap.client.WebAuthnClient
import com.webauthn4j.ctap.client.transport.InProcessTransportAdaptor
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import com.webauthn4j.ctap.core.converter.jackson.PublicKeyCredentialSourceCBORModule
import com.webauthn4j.data.*
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput
import com.webauthn4j.server.ServerProperty
import java.util.*
import java.util.function.Supplier
import kotlin.reflect.KProperty

abstract class IntegrationTestCaseBase {

    private val objectConverterParameter = TestParameter {
        val jsonMapper = ObjectMapper()
        val cborMapper = ObjectMapper(CBORFactory())
        cborMapper.registerModule(JavaTimeModule())
        cborMapper.registerModule(CtapCBORModule())
        cborMapper.registerModule(PublicKeyCredentialSourceCBORModule())
        cborMapper.registerModule(KotlinModule())
        ObjectConverter(jsonMapper, cborMapper)
    }
    var objectConverter by objectConverterParameter

    val authenticator = Authenticator()
    val clientPlatform = ClientPlatform()
    val relyingParty = RelyingParty()


    inner class Authenticator {
        private val attestationStatementGeneratorParameter = TestParameter<AttestationStatementProvider> { PackedBasicAttestationStatementProvider.createWithDemoAttestationKey() }
        private val fidoU2FAttestationStatementGeneratorParameter = TestParameter { FIDOU2FBasicAttestationStatementProvider.createWithDemoAttestationKey() }
        private val clientPINParameter = TestParameter { "clientPIN" }
        private val aaguidParameter = TestParameter { AAGUID(UUID.randomUUID()) }
        private val platformSettingParameter = TestParameter { PlatformSetting.CROSS_PLATFORM }
        private val residentKeySettingParameter = TestParameter { ResidentKeySetting.IF_REQUIRED }
        private val clientPINSettingParameter = TestParameter { ClientPINSetting.ENABLED }
        private val resetProtectionSettingParameter =
            TestParameter { ResetProtectionSetting.DISABLED }
        private val userPresenceSettingParameter = TestParameter { UserPresenceSetting.SUPPORTED }
        private val userVerificationSettingParameter =
            TestParameter { UserVerificationSetting.READY }
        private val algorithmsParameter = TestParameter { setOf(COSEAlgorithmIdentifier.ES256) }
        private val credentialSelectorSettingParameter =
            TestParameter { CredentialSelectorSetting.CLIENT_PLATFORM }
        private val ctapAuthenticatorSettingsParameter = TestParameter {
            CtapAuthenticatorSettings(
                aaguid,
                platformSetting,
                residentKeySetting,
                clientPINSetting,
                resetProtectionSetting,
                userPresenceSetting,
                userVerificationSetting,
                credentialSelectorSetting
            )
        }.depends(
            aaguidParameter,
            platformSettingParameter,
            residentKeySettingParameter,
            clientPINParameter,
            resetProtectionSettingParameter,
            userPresenceSettingParameter,
            userVerificationSettingParameter,
            credentialSelectorSettingParameter
        )
        private val credentialSelectionHandlerParameter =
            TestParameter<CredentialSelectionHandler> {
                object : CredentialSelectionHandler {
                    override suspend fun select(list: List<Credential>): Credential =
                        list.first()
                }
            }
        private val authenticatorPropertyStoreParameter =
            TestParameter<AuthenticatorPropertyStore> {
                InMemoryAuthenticatorPropertyStore().also {
                    it.saveClientPIN(clientPIN.toByteArray())
                    it.algorithms = algorithms
                }
            }.depends(clientPINParameter, algorithmsParameter)
        internal val ctapAuthenticatorParameter = TestParameter {
            val ctapAuthenticator = CtapAuthenticator(
                attestationStatementGenerator,
                fidoU2FAttestationStatementGenerator,
                emptyList(),
                authenticatorPropertyStore,
                objectConverter,
                ctapAuthenticatorSettings
            )
            ctapAuthenticator.credentialSelectionHandler = credentialSelectionHandler
            ctapAuthenticator
        }.depends(
            attestationStatementGeneratorParameter,
            authenticatorPropertyStoreParameter,
            objectConverterParameter,
            ctapAuthenticatorSettingsParameter,
            credentialSelectionHandlerParameter
        )


        var attestationStatementGenerator by attestationStatementGeneratorParameter
        val fidoU2FAttestationStatementGenerator by fidoU2FAttestationStatementGeneratorParameter
        var clientPIN by clientPINParameter
        var aaguid by aaguidParameter
        var platformSetting by platformSettingParameter
        var residentKeySetting by residentKeySettingParameter
        var clientPINSetting by clientPINSettingParameter
        var resetProtectionSetting by resetProtectionSettingParameter
        var userPresenceSetting by userPresenceSettingParameter
        var userVerificationSetting by userVerificationSettingParameter
        var algorithms by algorithmsParameter
        var credentialSelectorSetting by credentialSelectorSettingParameter
        var ctapAuthenticatorSettings by ctapAuthenticatorSettingsParameter
        var credentialSelectionHandler by credentialSelectionHandlerParameter
        var authenticatorPropertyStore by authenticatorPropertyStoreParameter
        val ctapAuthenticator by ctapAuthenticatorParameter
    }

    inner class ClientPlatform {
        private val ctapClientParameter =
            TestParameter { CtapAuthenticatorHandle(InProcessTransportAdaptor(authenticator.ctapAuthenticator)) }.depends(
                authenticator.ctapAuthenticatorParameter
            )
        private val ctapServiceParameter =
            TestParameter { CtapClient(ctapClient) }.depends(ctapClientParameter)
        private val webAuthnAPIClientParameter =
            TestParameter { WebAuthnClient(listOf(ctapClient), objectConverter) }.depends(
                ctapClientParameter,
                objectConverterParameter
            )

        var ctapClient by ctapClientParameter
        var ctapService by ctapServiceParameter
        var webAuthnAPIClient by webAuthnAPIClientParameter


    }

    inner class RelyingParty {
        private val webAuthnManagerParameter =
            TestParameter { WebAuthnManager.createNonStrictWebAuthnManager() }
        private val challengeParameter = TestParameter { DefaultChallenge() }

        var webAuthnManager by webAuthnManagerParameter

        val registration = Registration()
        val authentication = Authentication()
        var challenge by challengeParameter

        inner class Registration {
            val frontend: Frontend = Frontend()
            val backend: Backend = Backend()

            inner class Frontend {
                private val rpIdParameter = TestParameter<String?> { "example.com" }
                private val rpNameParameter = TestParameter { "WebAuthn4J Integration Test" }
                private val rpParameter =
                    TestParameter { PublicKeyCredentialRpEntity(rpId, rpName) }.depends(
                        rpIdParameter,
                        rpNameParameter
                    )
                private val userIdParameter = TestParameter { ByteArray(32) }
                private val userNameParameter = TestParameter { "john.smith@example.com" }
                private val displayNameParameter = TestParameter { "John Smith" }
                private val userParameter = TestParameter {
                    PublicKeyCredentialUserEntity(
                        userId,
                        userName,
                        displayName
                    )
                }.depends(userIdParameter, userNameParameter, displayNameParameter)
                private val pubKeyCredParamsParameter = TestParameter {
                    listOf(
                        PublicKeyCredentialParameters(
                            PublicKeyCredentialType.PUBLIC_KEY,
                            COSEAlgorithmIdentifier.ES256
                        )
                    )
                }
                private val timeoutParameter = TestParameter<Long?> { null }
                private val excludeCredentialsParameter =
                    TestParameter<List<PublicKeyCredentialDescriptor>?> { null }
                private val authenticatorAttachmentParameter =
                    TestParameter<AuthenticatorAttachment?> { null }
                private val requireResidentKeyParameter = TestParameter { true }
                private val residentKeyParameter =
                    TestParameter { ResidentKeyRequirement.PREFERRED }
                private val userVerificationParameter =
                    TestParameter { UserVerificationRequirement.REQUIRED }
                private val authenticatorSelectionCriteriaParameter = TestParameter {
                    AuthenticatorSelectionCriteria(
                        authenticatorAttachment,
                        requireResidentKey,
                        residentKey,
                        userVerification
                    )
                }.depends(
                    authenticatorAttachmentParameter,
                    requireResidentKeyParameter,
                    residentKeyParameter,
                    userVerificationParameter
                )
                private val attestationParameter =
                    TestParameter { AttestationConveyancePreference.DIRECT }
                private val extensionsParameter =
                    TestParameter<AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>?> { null }
                private val publicKeyCredentialCreationOptionsParameter = TestParameter {
                    PublicKeyCredentialCreationOptions(
                        rp,
                        user,
                        challenge,
                        pubKeyCredParams,
                        timeout,
                        excludeCredentials,
                        authenticatorSelectionCriteria,
                        attestation,
                        extensions
                    )
                }.depends(
                    rpParameter,
                    userParameter,
                    challengeParameter,
                    pubKeyCredParamsParameter,
                    timeoutParameter,
                    excludeCredentialsParameter,
                    authenticatorSelectionCriteriaParameter,
                    attestationParameter,
                    extensionsParameter
                )
                private val originParameter = TestParameter { Origin("https://example.com") }
                private val clientPINParameter = TestParameter { "clientPIN" }
                private val clientPropertyParameter =
                    TestParameter { ClientProperty(origin, clientPIN) }.depends(
                        originParameter,
                        clientPINParameter
                    )

                var rpId by rpIdParameter
                var rpName by rpNameParameter
                var rp by rpParameter
                var userId by userIdParameter
                var userName by userNameParameter
                var displayName by displayNameParameter
                var user by userParameter
                var pubKeyCredParams by pubKeyCredParamsParameter
                var timeout by timeoutParameter
                var excludeCredentials by excludeCredentialsParameter
                var authenticatorAttachment by authenticatorAttachmentParameter
                var requireResidentKey by requireResidentKeyParameter
                var residentKey by residentKeyParameter
                var userVerification by userVerificationParameter
                var authenticatorSelectionCriteria by authenticatorSelectionCriteriaParameter
                var attestation by attestationParameter
                var extensions by extensionsParameter
                var publicKeyCredentialCreationOptions by publicKeyCredentialCreationOptionsParameter
                var origin by originParameter
                var clientPIN by clientPINParameter
                var clientProperty by clientPropertyParameter
            }

            inner class Backend {
                private val originParameter = TestParameter { Origin("https://example.com") }
                private val rpIdParameter = TestParameter { "example.com" }
                private val challengeParameter =
                    TestParameter { this@RelyingParty.challenge }.depends(this@RelyingParty.challengeParameter)
                private val tokenBindingIdParameter = TestParameter<ByteArray?> { null }
                private val serverPropertyParameter = TestParameter {
                    ServerProperty(
                        origin,
                        rpId,
                        challenge,
                        tokenBindingId
                    )
                }.depends(
                    originParameter,
                    rpIdParameter,
                    challengeParameter,
                    tokenBindingIdParameter
                )
                private val userVerificationRequiredParameter = TestParameter { true }
                private val userPresenceRequiredParameter = TestParameter { true }

                var origin by originParameter
                var rpId by rpIdParameter
                var challenge by challengeParameter
                var tokenBindingId by tokenBindingIdParameter
                var serverProperty by serverPropertyParameter
                var userVerificationRequired by userVerificationRequiredParameter
                var userPresenceRequired by userPresenceRequiredParameter
            }
        }

        inner class Authentication {
            val frontend: Frontend = Frontend()
            val backend: Backend = Backend()

            inner class Frontend {
                private val timeoutParameter = TestParameter<Long?> { null }
                private val rpIdParameter = TestParameter<String?> { "example.com" }
                private val allowCredentialsParameter =
                    TestParameter<List<PublicKeyCredentialDescriptor>?> { null }
                private val userVerificationParameter =
                    TestParameter { UserVerificationRequirement.REQUIRED }
                private val extensionsParameter =
                    TestParameter<AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput>?> { null }
                private val publicKeyCredentialRequestOptionsParameter = TestParameter {
                    PublicKeyCredentialRequestOptions(
                        challenge,
                        timeout,
                        rpId,
                        allowCredentials,
                        userVerification,
                        extensions
                    )
                }.depends(
                    timeoutParameter,
                    rpIdParameter,
                    allowCredentialsParameter,
                    userVerificationParameter,
                    extensionsParameter
                ) //this@RelyingParty.challengeParameter,
                private val originParameter = TestParameter { Origin("https://example.com") }
                private val clientPINParameter = TestParameter { "clientPIN" }
                private val clientPropertyParameter =
                    TestParameter { ClientProperty(origin, clientPIN) }.depends(
                        originParameter,
                        clientPINParameter
                    )

                var timeout by timeoutParameter
                var rpId by rpIdParameter
                var allowCredentials by allowCredentialsParameter
                var userVerification by userVerificationParameter
                var extensions by extensionsParameter
                var publicKeyCredentialRequestOptions by publicKeyCredentialRequestOptionsParameter
                var origin by originParameter
                var clientPIN by clientPINParameter
                var clientProperty by clientPropertyParameter
            }

            inner class Backend {
                private val originParameter = TestParameter { Origin("https://example.com") }
                private val rpIdParameter = TestParameter { "example.com" }
                private val challengeParameter =
                    TestParameter { this@RelyingParty.challenge }//.depends(this@RelyingParty.challengeParameter)
                private val tokenBindingIdParameter = TestParameter<ByteArray?> { null }
                private val userVerificationRequiredParameter = TestParameter { true }
                private val userPresenceRequiredParameter = TestParameter { true }

                private val serverPropertyParameter = TestParameter {
                    ServerProperty(origin, rpId, challenge, tokenBindingId)
                }.depends(
                    originParameter,
                    rpIdParameter,
                    challengeParameter,
                    tokenBindingIdParameter
                )

                var origin by originParameter
                var rpId by rpIdParameter
                var challenge by challengeParameter
                var tokenBindingId by tokenBindingIdParameter
                var serverProperty by serverPropertyParameter
                var userVerificationRequired by userVerificationRequiredParameter
                var userPresenceRequired by userPresenceRequiredParameter
            }
        }
    }

    class TestParameter<T>(private var supplier: Supplier<T>) {
        private var isDefault = true
        private var cached: T? = null
        private var needsSupplierReevaluation = true
        private val dependants = mutableListOf<TestParameter<out Any?>>()

        operator fun getValue(thisRef: Any?, property: KProperty<*>): T {
            if (needsSupplierReevaluation) {
                cached = supplier.get()
                needsSupplierReevaluation = false
            }
            @Suppress("UNCHECKED_CAST")
            return cached as T
        }

        operator fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
            isDefault = false
            supplier = Supplier { value }
            needsSupplierReevaluation = true
            dependants.forEach { it.needsSupplierReevaluation = true }
        }

        fun depends(vararg parameters: TestParameter<out Any?>): TestParameter<T> {
            parameters.forEach { it.dependedBy(this) }
            return this
        }

        private fun dependedBy(parameter: TestParameter<out Any?>) {
            dependants.add(parameter)
        }
    }
}