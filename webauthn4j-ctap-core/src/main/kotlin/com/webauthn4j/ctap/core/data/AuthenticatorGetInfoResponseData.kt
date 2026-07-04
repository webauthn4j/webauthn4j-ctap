package com.webauthn4j.ctap.core.data
import com.webauthn4j.data.PinProtocolVersion

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.data.options.*
import com.webauthn4j.data.AuthenticatorTransport
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.UserVerificationMethod
import com.webauthn4j.data.attestation.authenticator.AAGUID

// §6.4 authenticatorGetInfo (0x04)
class AuthenticatorGetInfoResponseData : CtapResponseData {

    companion object {

        @JvmStatic
        @JsonCreator
        fun createFromCbor(
            @JsonProperty("1") versions: List<String>,
            @JsonProperty("2") extensions: List<String>?,
            @JsonProperty("3") aaguid: AAGUID,
            @JsonProperty("4") options: Options?,
            @JsonProperty("5") maxMsgSize: Long?,
            @JsonProperty("6") pinUvAuthProtocols: List<PinProtocolVersion>?,
            @JsonProperty("7") maxCredentialCountInList: Long?,
            @JsonProperty("8") maxCredentialIdLength: Long?,
            @JsonProperty("9") transports: Set<AuthenticatorTransport>?,
            @JsonProperty("10") algorithms: List<PublicKeyCredentialParameters>?,
            @JsonProperty("11") maxSerializedLargeBlobArray: Long?,
            @JsonProperty("12") forcePINChange: Boolean?,
            @JsonProperty("13") minPINLength: Long?,
            @JsonProperty("14") firmwareVersion: Long?,
            @JsonProperty("15") maxCredBlobLength: Long?,
            @JsonProperty("16") maxRPIDsForSetMinPINLength: Long?,
            @JsonProperty("17") preferredPlatformUvAttempts: Long?,
            @JsonProperty("18") uvModality: Set<UserVerificationMethod>?,
            @JsonProperty("19") certifications: Map<String, Any>?,
            @JsonProperty("20") remainingDiscoverableCredentials: Long?,
            @JsonProperty("21") vendorPrototypeConfigCommands: List<Long>?,
            @JsonProperty("22") attestationFormats: List<String>?,
            @JsonProperty("23") uvCountSinceLastPinEntry: Long?,
            @JsonProperty("24") longTouchForReset: Boolean?,
            @JsonProperty("25") encIdentifier: String?,
            @JsonProperty("26") transportsForReset: Set<AuthenticatorTransport>?,
            @JsonProperty("27") pinComplexityPolicy: Boolean?,
            @JsonProperty("28") pinComplexityPolicyURL: String?,
            @JsonProperty("29") maxPINLength: Long?,
            @JsonProperty("30") encCredStoreState: String?,
            @JsonProperty("31") authenticatorConfigCommands: List<Long>?
        ): AuthenticatorGetInfoResponseData {
            return AuthenticatorGetInfoResponseData(
                versions,
                extensions,
                aaguid,
                options,
                maxMsgSize?.toUInt(),
                pinUvAuthProtocols,
                maxCredentialCountInList?.toUInt(),
                maxCredentialIdLength?.toUInt(),
                transports,
                algorithms,
                maxSerializedLargeBlobArray?.toUInt(),
                forcePINChange,
                minPINLength?.toUInt(),
                firmwareVersion?.toUInt(),
                maxCredBlobLength?.toUInt(),
                maxRPIDsForSetMinPINLength?.toUInt(),
                preferredPlatformUvAttempts?.toUInt(),
                uvModality,
                certifications,
                remainingDiscoverableCredentials?.toUInt(),
                vendorPrototypeConfigCommands?.map { it.toUInt() },
                attestationFormats,
                uvCountSinceLastPinEntry?.toUInt(),
                longTouchForReset,
                encIdentifier,
                transportsForReset,
                pinComplexityPolicy,
                pinComplexityPolicyURL,
                maxPINLength?.toUInt(),
                encCredStoreState,
                authenticatorConfigCommands?.map { it.toUInt() }
            )
        }
    }

    // §6.4 versions (0x01): Required
    val versions: List<String>
    // §6.4 extensions (0x02): Optional
    val extensions: List<String>?
    // §6.4 aaguid (0x03): Required
    val aaguid: AAGUID
    // §6.4 options (0x04): Optional
    val options: Options?
    // §6.4 maxMsgSize (0x05): Optional
    val maxMsgSize: UInt?
    // §6.4 pinUvAuthProtocols (0x06): Optional
    val pinUvAuthProtocols: List<PinProtocolVersion>?
    // §6.4 maxCredentialCountInList (0x07): Optional
    val maxCredentialCountInList: UInt?
    // §6.4 maxCredentialIdLength (0x08): Optional
    val maxCredentialIdLength: UInt?
    // §6.4 transports (0x09): Optional
    val transports: Set<AuthenticatorTransport>?
    // §6.4 algorithms (0x0A): Optional
    val algorithms: List<PublicKeyCredentialParameters>?
    // §6.4 maxSerializedLargeBlobArray (0x0B): Optional
    val maxSerializedLargeBlobArray: UInt?
    // §6.4 forcePINChange (0x0C): Optional
    val forcePINChange: Boolean?
    // §6.4 minPINLength (0x0D): Optional
    val minPINLength: UInt?
    // §6.4 firmwareVersion (0x0E): Optional
    val firmwareVersion: UInt?
    // §6.4 maxCredBlobLength (0x0F): Optional
    val maxCredBlobLength: UInt?
    // §6.4 maxRPIDsForSetMinPINLength (0x10): Optional
    val maxRPIDsForSetMinPINLength: UInt?
    // §6.4 preferredPlatformUvAttempts (0x11): Optional
    val preferredPlatformUvAttempts: UInt?
    // §6.4 uvModality (0x12): Optional
    val uvModality: Set<UserVerificationMethod>?
    // §6.4 certifications (0x13): Optional
    val certifications: Map<String, Any>?
    // §6.4 remainingDiscoverableCredentials (0x14): Optional
    val remainingDiscoverableCredentials: UInt?
    // §6.4 vendorPrototypeConfigCommands (0x15): Optional
    val vendorPrototypeConfigCommands: List<UInt>?
    // §6.4 attestationFormats (0x16): Optional
    val attestationFormats: List<String>?
    // §6.4 uvCountSinceLastPinEntry (0x17): Optional
    val uvCountSinceLastPinEntry: UInt?
    // §6.4 longTouchForReset (0x18): Optional
    val longTouchForReset: Boolean?
    // §6.4 encIdentifier (0x19): Optional
    val encIdentifier: String?
    // §6.4 transportsForReset (0x1A): Optional
    val transportsForReset: Set<AuthenticatorTransport>?
    // §6.4 pinComplexityPolicy (0x1B): Optional
    val pinComplexityPolicy: Boolean?
    // §6.4 pinComplexityPolicyURL (0x1C): Optional
    val pinComplexityPolicyURL: String?
    // §6.4 maxPINLength (0x1D): Optional
    val maxPINLength: UInt?
    // §6.4 encCredStoreState (0x1E): Optional
    val encCredStoreState: String?
    // §6.4 authenticatorConfigCommands (0x1F): Optional
    val authenticatorConfigCommands: List<UInt>?

    constructor(
        versions: List<String>,
        extensions: List<String>?,
        aaguid: AAGUID,
        options: Options?,
        maxMsgSize: UInt?,
        pinUvAuthProtocols: List<PinProtocolVersion>?,
        maxCredentialCountInList: UInt?,
        maxCredentialIdLength: UInt?,
        transports: Set<AuthenticatorTransport>?,
        algorithms: List<PublicKeyCredentialParameters>? = null,
        maxSerializedLargeBlobArray: UInt? = null,
        forcePINChange: Boolean? = null,
        minPINLength: UInt? = null,
        firmwareVersion: UInt? = null,
        maxCredBlobLength: UInt? = null,
        maxRPIDsForSetMinPINLength: UInt? = null,
        preferredPlatformUvAttempts: UInt? = null,
        uvModality: Set<UserVerificationMethod>? = null,
        certifications: Map<String, Any>? = null,
        remainingDiscoverableCredentials: UInt? = null,
        vendorPrototypeConfigCommands: List<UInt>? = null,
        attestationFormats: List<String>? = null,
        uvCountSinceLastPinEntry: UInt? = null,
        longTouchForReset: Boolean? = null,
        encIdentifier: String? = null,
        transportsForReset: Set<AuthenticatorTransport>? = null,
        pinComplexityPolicy: Boolean? = null,
        pinComplexityPolicyURL: String? = null,
        maxPINLength: UInt? = null,
        encCredStoreState: String? = null,
        authenticatorConfigCommands: List<UInt>? = null
    ) {
        this.versions = versions.toList()
        this.extensions = extensions?.toList()
        this.aaguid = aaguid
        this.options = options
        this.maxMsgSize = maxMsgSize
        this.pinUvAuthProtocols = pinUvAuthProtocols?.toList()
        this.maxCredentialCountInList = maxCredentialCountInList
        this.maxCredentialIdLength = maxCredentialIdLength
        this.transports = transports
        this.algorithms = algorithms
        this.maxSerializedLargeBlobArray = maxSerializedLargeBlobArray
        this.forcePINChange = forcePINChange
        this.minPINLength = minPINLength
        this.firmwareVersion = firmwareVersion
        this.maxCredBlobLength = maxCredBlobLength
        this.maxRPIDsForSetMinPINLength = maxRPIDsForSetMinPINLength
        this.preferredPlatformUvAttempts = preferredPlatformUvAttempts
        this.uvModality = uvModality
        this.certifications = certifications
        this.remainingDiscoverableCredentials = remainingDiscoverableCredentials
        this.vendorPrototypeConfigCommands = vendorPrototypeConfigCommands
        this.attestationFormats = attestationFormats
        this.uvCountSinceLastPinEntry = uvCountSinceLastPinEntry
        this.longTouchForReset = longTouchForReset
        this.encIdentifier = encIdentifier
        this.transportsForReset = transportsForReset
        this.pinComplexityPolicy = pinComplexityPolicy
        this.pinComplexityPolicyURL = pinComplexityPolicyURL
        this.maxPINLength = maxPINLength
        this.encCredStoreState = encCredStoreState
        this.authenticatorConfigCommands = authenticatorConfigCommands
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorGetInfoResponseData

        if (versions != other.versions) return false
        if (extensions != other.extensions) return false
        if (aaguid != other.aaguid) return false
        if (options != other.options) return false
        if (maxMsgSize != other.maxMsgSize) return false
        if (pinUvAuthProtocols != other.pinUvAuthProtocols) return false
        if (maxCredentialCountInList != other.maxCredentialCountInList) return false
        if (maxCredentialIdLength != other.maxCredentialIdLength) return false
        if (transports != other.transports) return false
        if (algorithms != other.algorithms) return false
        if (maxSerializedLargeBlobArray != other.maxSerializedLargeBlobArray) return false
        if (forcePINChange != other.forcePINChange) return false
        if (minPINLength != other.minPINLength) return false
        if (firmwareVersion != other.firmwareVersion) return false
        if (maxCredBlobLength != other.maxCredBlobLength) return false
        if (maxRPIDsForSetMinPINLength != other.maxRPIDsForSetMinPINLength) return false
        if (preferredPlatformUvAttempts != other.preferredPlatformUvAttempts) return false
        if (uvModality != other.uvModality) return false
        if (certifications != other.certifications) return false
        if (remainingDiscoverableCredentials != other.remainingDiscoverableCredentials) return false
        if (vendorPrototypeConfigCommands != other.vendorPrototypeConfigCommands) return false
        if (attestationFormats != other.attestationFormats) return false
        if (uvCountSinceLastPinEntry != other.uvCountSinceLastPinEntry) return false
        if (longTouchForReset != other.longTouchForReset) return false
        if (encIdentifier != other.encIdentifier) return false
        if (transportsForReset != other.transportsForReset) return false
        if (pinComplexityPolicy != other.pinComplexityPolicy) return false
        if (pinComplexityPolicyURL != other.pinComplexityPolicyURL) return false
        if (maxPINLength != other.maxPINLength) return false
        if (encCredStoreState != other.encCredStoreState) return false
        if (authenticatorConfigCommands != other.authenticatorConfigCommands) return false

        return true
    }

    override fun hashCode(): Int {
        var result = versions.hashCode()
        result = 31 * result + (extensions?.hashCode() ?: 0)
        result = 31 * result + aaguid.hashCode()
        result = 31 * result + (options?.hashCode() ?: 0)
        result = 31 * result + (maxMsgSize?.hashCode() ?: 0)
        result = 31 * result + (pinUvAuthProtocols?.hashCode() ?: 0)
        result = 31 * result + (maxCredentialCountInList?.hashCode() ?: 0)
        result = 31 * result + (maxCredentialIdLength?.hashCode() ?: 0)
        result = 31 * result + (transports?.hashCode() ?: 0)
        result = 31 * result + (algorithms?.hashCode() ?: 0)
        result = 31 * result + (maxSerializedLargeBlobArray?.hashCode() ?: 0)
        result = 31 * result + (forcePINChange?.hashCode() ?: 0)
        result = 31 * result + (minPINLength?.hashCode() ?: 0)
        result = 31 * result + (firmwareVersion?.hashCode() ?: 0)
        result = 31 * result + (maxCredBlobLength?.hashCode() ?: 0)
        result = 31 * result + (maxRPIDsForSetMinPINLength?.hashCode() ?: 0)
        result = 31 * result + (preferredPlatformUvAttempts?.hashCode() ?: 0)
        result = 31 * result + (uvModality?.hashCode() ?: 0)
        result = 31 * result + (certifications?.hashCode() ?: 0)
        result = 31 * result + (remainingDiscoverableCredentials?.hashCode() ?: 0)
        result = 31 * result + (vendorPrototypeConfigCommands?.hashCode() ?: 0)
        result = 31 * result + (attestationFormats?.hashCode() ?: 0)
        result = 31 * result + (uvCountSinceLastPinEntry?.hashCode() ?: 0)
        result = 31 * result + (longTouchForReset?.hashCode() ?: 0)
        result = 31 * result + (encIdentifier?.hashCode() ?: 0)
        result = 31 * result + (transportsForReset?.hashCode() ?: 0)
        result = 31 * result + (pinComplexityPolicy?.hashCode() ?: 0)
        result = 31 * result + (pinComplexityPolicyURL?.hashCode() ?: 0)
        result = 31 * result + (maxPINLength?.hashCode() ?: 0)
        result = 31 * result + (encCredStoreState?.hashCode() ?: 0)
        result = 31 * result + (authenticatorConfigCommands?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "AuthenticatorGetInfoResponseData(versions=$versions, extensions=$extensions, aaguid=$aaguid, options=$options, maxMsgSize=$maxMsgSize, pinUvAuthProtocols=$pinUvAuthProtocols, maxCredentialCountInList=$maxCredentialCountInList, maxCredentialIdLength=$maxCredentialIdLength, transports=$transports, algorithms=$algorithms)"
    }

    // §6.4 options
    class Options @JsonCreator constructor(
        @param:JsonProperty("plat") val plat: PlatformOption?,
        @param:JsonProperty("rk") val rk: ResidentKeyOption?,
        @param:JsonProperty("clientPin") val clientPin: ClientPINOption?,
        @param:JsonProperty("up") val up: UserPresenceOption?,
        @param:JsonProperty("uv") val uv: UserVerificationOption?,
        @param:JsonProperty("pinUvAuthToken") val pinUvAuthToken: PinUvAuthTokenOption?,
        @param:JsonProperty("noMcGaPermissionsWithClientPin") val noMcGaPermissionsWithClientPin: NoMcGaPermissionsWithClientPinOption?,
        @param:JsonProperty("largeBlobs") val largeBlobs: LargeBlobsOption?,
        @param:JsonProperty("ep") val ep: EnterpriseAttestationOption?,
        @param:JsonProperty("bioEnroll") val bioEnroll: BioEnrollOption?,
        @param:JsonProperty("userVerificationMgmtPreview") val userVerificationMgmtPreview: UserVerificationMgmtPreviewOption?,
        @param:JsonProperty("uvBioEnroll") val uvBioEnroll: UvBioEnrollOption?,
        @param:JsonProperty("authnrCfg") val authnrCfg: AuthnrCfgOption?,
        @param:JsonProperty("uvAcfg") val uvAcfg: UvAcfgOption?,
        @param:JsonProperty("credMgmt") val credMgmt: CredMgmtOption?,
        @param:JsonProperty("perCredMgmtRO") val perCredMgmtRO: PerCredMgmtROOption?,
        @param:JsonProperty("credentialMgmtPreview") val credentialMgmtPreview: CredentialMgmtPreviewOption?,
        @param:JsonProperty("setMinPINLength") val setMinPINLength: SetMinPINLengthOption?,
        @param:JsonProperty("makeCredUvNotRqd") val makeCredUvNotRqd: MakeCredUvNotRqdOption?,
        @param:JsonProperty("alwaysUv") val alwaysUv: AlwaysUvOption?
    ) {

        constructor(
            plat: PlatformOption?,
            rk: ResidentKeyOption?,
            clientPin: ClientPINOption?,
            up: UserPresenceOption?,
            uv: UserVerificationOption?,
            alwaysUv: AlwaysUvOption?,
            makeCredUvNotRqd: MakeCredUvNotRqdOption?
        ) : this(
            plat, rk, clientPin, up, uv,
            null, null, null, null, null, null, null, null, null, null, null, null, null,
            makeCredUvNotRqd, alwaysUv
        )

        override fun toString(): String {
            return "Options(plat=${plat?.value}, rk=${rk?.value}, clientPin=${clientPin?.value}, up=${up?.value}, uv=${uv?.value}, pinUvAuthToken=${pinUvAuthToken?.value}, noMcGaPermissionsWithClientPin=${noMcGaPermissionsWithClientPin?.value}, largeBlobs=${largeBlobs?.value}, ep=${ep?.value}, bioEnroll=${bioEnroll?.value}, userVerificationMgmtPreview=${userVerificationMgmtPreview?.value}, uvBioEnroll=${uvBioEnroll?.value}, authnrCfg=${authnrCfg?.value}, uvAcfg=${uvAcfg?.value}, credMgmt=${credMgmt?.value}, perCredMgmtRO=${perCredMgmtRO?.value}, credentialMgmtPreview=${credentialMgmtPreview?.value}, setMinPINLength=${setMinPINLength?.value}, makeCredUvNotRqd=${makeCredUvNotRqd?.value}, alwaysUv=${alwaysUv?.value})"
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Options

            if (plat != other.plat) return false
            if (rk != other.rk) return false
            if (clientPin != other.clientPin) return false
            if (up != other.up) return false
            if (uv != other.uv) return false
            if (pinUvAuthToken != other.pinUvAuthToken) return false
            if (noMcGaPermissionsWithClientPin != other.noMcGaPermissionsWithClientPin) return false
            if (largeBlobs != other.largeBlobs) return false
            if (ep != other.ep) return false
            if (bioEnroll != other.bioEnroll) return false
            if (userVerificationMgmtPreview != other.userVerificationMgmtPreview) return false
            if (uvBioEnroll != other.uvBioEnroll) return false
            if (authnrCfg != other.authnrCfg) return false
            if (uvAcfg != other.uvAcfg) return false
            if (credMgmt != other.credMgmt) return false
            if (perCredMgmtRO != other.perCredMgmtRO) return false
            if (credentialMgmtPreview != other.credentialMgmtPreview) return false
            if (setMinPINLength != other.setMinPINLength) return false
            if (makeCredUvNotRqd != other.makeCredUvNotRqd) return false
            if (alwaysUv != other.alwaysUv) return false

            return true
        }

        override fun hashCode(): Int {
            var result = plat?.hashCode() ?: 0
            result = 31 * result + (rk?.hashCode() ?: 0)
            result = 31 * result + (clientPin?.hashCode() ?: 0)
            result = 31 * result + (up?.hashCode() ?: 0)
            result = 31 * result + (uv?.hashCode() ?: 0)
            result = 31 * result + (pinUvAuthToken?.hashCode() ?: 0)
            result = 31 * result + (noMcGaPermissionsWithClientPin?.hashCode() ?: 0)
            result = 31 * result + (largeBlobs?.hashCode() ?: 0)
            result = 31 * result + (ep?.hashCode() ?: 0)
            result = 31 * result + (bioEnroll?.hashCode() ?: 0)
            result = 31 * result + (userVerificationMgmtPreview?.hashCode() ?: 0)
            result = 31 * result + (uvBioEnroll?.hashCode() ?: 0)
            result = 31 * result + (authnrCfg?.hashCode() ?: 0)
            result = 31 * result + (uvAcfg?.hashCode() ?: 0)
            result = 31 * result + (credMgmt?.hashCode() ?: 0)
            result = 31 * result + (perCredMgmtRO?.hashCode() ?: 0)
            result = 31 * result + (credentialMgmtPreview?.hashCode() ?: 0)
            result = 31 * result + (setMinPINLength?.hashCode() ?: 0)
            result = 31 * result + (makeCredUvNotRqd?.hashCode() ?: 0)
            result = 31 * result + (alwaysUv?.hashCode() ?: 0)
            return result
        }

    }
}
