package com.webauthn4j.ctap.authenticator.execution

import com.webauthn4j.ctap.authenticator.CredentialManagementSession
import com.webauthn4j.ctap.authenticator.CtapAuthenticatorSession
import com.webauthn4j.ctap.authenticator.PinUvAuthProtocol
import com.webauthn4j.ctap.authenticator.data.credential.ResidentUserCredential
import com.webauthn4j.ctap.core.data.AuthenticatorCredentialManagementRequest
import com.webauthn4j.ctap.core.data.AuthenticatorCredentialManagementResponse
import com.webauthn4j.ctap.core.data.AuthenticatorCredentialManagementResponseData
import com.webauthn4j.ctap.core.data.CredentialManagementSubCommand
import com.webauthn4j.ctap.core.data.CtapStatusCode
import com.webauthn4j.ctap.core.data.PinUvAuthTokenPermission
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.authenticator.RSACOSEKey
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.util.MessageDigestUtil
import org.slf4j.LoggerFactory
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

/**
 * authenticatorCredentialManagement (0x0A) command execution
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorCredentialManagement">CTAP 2.3 §6.8 authenticatorCredentialManagement</a>
 */
internal class CredentialManagementExecution(
    private val ctapAuthenticatorSession: CtapAuthenticatorSession,
    private val request: AuthenticatorCredentialManagementRequest
) : CtapCommandExecutionBase<AuthenticatorCredentialManagementRequest, AuthenticatorCredentialManagementResponse>(
    ctapAuthenticatorSession,
    request
) {

    private val logger = LoggerFactory.getLogger(CredentialManagementExecution::class.java)
    override val commandName: String = "CredentialManagement"

    override suspend fun validate() {
        // Validation is done within each subcommand handler
    }

    override suspend fun doExecute(): AuthenticatorCredentialManagementResponse {
        return when (request.subCommand) {
            CredentialManagementSubCommand.GET_CREDS_METADATA -> {
                logger.debug("Processing credentialManagement getCredsMetadata sub-command")
                handleGetCredsMetadata()
            }
            CredentialManagementSubCommand.ENUMERATE_RPS_BEGIN -> {
                logger.debug("Processing credentialManagement enumerateRPsBegin sub-command")
                handleEnumerateRPsBegin()
            }
            CredentialManagementSubCommand.ENUMERATE_RPS_GET_NEXT_RP -> {
                logger.debug("Processing credentialManagement enumerateRPsGetNextRP sub-command")
                handleEnumerateRPsGetNextRP()
            }
            CredentialManagementSubCommand.ENUMERATE_CREDENTIALS_BEGIN -> {
                logger.debug("Processing credentialManagement enumerateCredentialsBegin sub-command")
                handleEnumerateCredentialsBegin()
            }
            CredentialManagementSubCommand.ENUMERATE_CREDENTIALS_GET_NEXT_CREDENTIAL -> {
                logger.debug("Processing credentialManagement enumerateCredentialsGetNextCredential sub-command")
                handleEnumerateCredentialsGetNextCredential()
            }
            CredentialManagementSubCommand.DELETE_CREDENTIAL -> {
                logger.debug("Processing credentialManagement deleteCredential sub-command")
                handleDeleteCredential()
            }
            CredentialManagementSubCommand.UPDATE_USER_INFORMATION -> {
                logger.debug("Processing credentialManagement updateUserInformation sub-command")
                handleUpdateUserInformation()
            }
        }
    }

    override fun createErrorResponse(statusCode: CtapStatusCode): AuthenticatorCredentialManagementResponse {
        return AuthenticatorCredentialManagementResponse(statusCode)
    }

    // ========================================================================
    // Subcommand: getCredsMetadata (0x01)
    // ========================================================================

    private fun handleGetCredsMetadata(): AuthenticatorCredentialManagementResponse {
        // Verify pinUvAuthParam with message = subCommand byte only
        val message = byteArrayOf(request.subCommand.value.toByte())
        verifyPinUvAuthParam(message, requireNoPermissionsRpId = true)

        val count = ctapAuthenticatorSession.authenticatorPropertyStore.countAllUserCredentials()
        val responseData = AuthenticatorCredentialManagementResponseData(
            existingResidentCredentialsCount = count.toUInt(),
            maxPossibleRemainingResidentCredentialsCount = Int.MAX_VALUE.toUInt(),
            rp = null,
            rpIDHash = null,
            totalRPs = null,
            user = null,
            credentialID = null,
            publicKey = null,
            totalCredentials = null,
            credProtect = null
        )
        return AuthenticatorCredentialManagementResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    // ========================================================================
    // Subcommand: enumerateRPsBegin (0x02)
    // ========================================================================

    private fun handleEnumerateRPsBegin(): AuthenticatorCredentialManagementResponse {
        // Verify pinUvAuthParam with message = subCommand byte only
        val message = byteArrayOf(request.subCommand.value.toByte())
        verifyPinUvAuthParam(message, requireNoPermissionsRpId = true)

        val rpIds = ctapAuthenticatorSession.authenticatorPropertyStore.loadAllRpIds().toList()
        if (rpIds.isEmpty()) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NO_CREDENTIALS)
        }

        val session = CredentialManagementSession(rpIds)
        ctapAuthenticatorSession.onGoingCredentialManagementRpSession = session

        val rpId = session.current()
        return buildRpResponse(rpId, session.totalItems.toUInt())
    }

    // ========================================================================
    // Subcommand: enumerateRPsGetNextRP (0x03)
    // ========================================================================

    private fun handleEnumerateRPsGetNextRP(): AuthenticatorCredentialManagementResponse {
        val session = ctapAuthenticatorSession.onGoingCredentialManagementRpSession
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)

        if (session.isExpired()) {
            ctapAuthenticatorSession.onGoingCredentialManagementRpSession = null
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
        }

        if (!session.hasNext()) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
        }

        val rpId = session.next()
        // No totalRPs for subsequent responses
        return buildRpResponse(rpId, null)
    }

    // ========================================================================
    // Subcommand: enumerateCredentialsBegin (0x04)
    // ========================================================================

    private fun handleEnumerateCredentialsBegin(): AuthenticatorCredentialManagementResponse {
        val subCommandParams = request.subCommandParams
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)

        val subCommandParamsBytes = ctapAuthenticatorSession.objectConverter.cborMapper
            .writeValueAsBytes(subCommandParams)
        val message = byteArrayOf(request.subCommand.value.toByte()) + subCommandParamsBytes
        verifyPinUvAuthParam(message, requireNoPermissionsRpId = true)

        val rpIDHash = subCommandParams.rpIDHash
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)

        // Find the RP ID by matching rpIDHash against all known RPs
        val allRpIds = ctapAuthenticatorSession.authenticatorPropertyStore.loadAllRpIds()
        val rpId = allRpIds.firstOrNull { id ->
            MessageDigestUtil.createSHA256().digest(id.toByteArray()).contentEquals(rpIDHash)
        } ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NO_CREDENTIALS)

        val credentials = ctapAuthenticatorSession.authenticatorPropertyStore.loadUserCredentials(rpId)
        if (credentials.isEmpty()) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NO_CREDENTIALS)
        }

        val session = CredentialManagementSession(credentials)
        ctapAuthenticatorSession.onGoingCredentialManagementCredentialSession = session

        val credential = session.current()
        return buildCredentialResponse(credential, session.totalItems.toUInt())
    }

    // ========================================================================
    // Subcommand: enumerateCredentialsGetNextCredential (0x05)
    // ========================================================================

    private fun handleEnumerateCredentialsGetNextCredential(): AuthenticatorCredentialManagementResponse {
        val session = ctapAuthenticatorSession.onGoingCredentialManagementCredentialSession
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)

        if (session.isExpired()) {
            ctapAuthenticatorSession.onGoingCredentialManagementCredentialSession = null
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
        }

        if (!session.hasNext()) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NOT_ALLOWED)
        }

        val credential = session.next()
        // No totalCredentials for subsequent responses
        return buildCredentialResponse(credential, null)
    }

    // ========================================================================
    // Subcommand: deleteCredential (0x06)
    // ========================================================================

    private fun handleDeleteCredential(): AuthenticatorCredentialManagementResponse {
        val subCommandParams = request.subCommandParams
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)

        val subCommandParamsBytes = ctapAuthenticatorSession.objectConverter.cborMapper
            .writeValueAsBytes(subCommandParams)
        val message = byteArrayOf(request.subCommand.value.toByte()) + subCommandParamsBytes
        verifyPinUvAuthParam(message, requireNoPermissionsRpId = false)

        val credentialID = subCommandParams.credentialID
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)

        val credential = findCredentialById(credentialID.id)
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NO_CREDENTIALS)

        // If permissionsRpId is set, it must match the RP ID of the target credential
        val protocol = resolveProtocol()
        val tokenRpId = protocol.tokenState.permissionsRpId
        if (tokenRpId != null && tokenRpId != credential.rpId) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        ctapAuthenticatorSession.authenticatorPropertyStore.removeUserCredential(credential.credentialId)

        return AuthenticatorCredentialManagementResponse(CtapStatusCode.CTAP2_OK)
    }

    // ========================================================================
    // Subcommand: updateUserInformation (0x07)
    // ========================================================================

    private fun handleUpdateUserInformation(): AuthenticatorCredentialManagementResponse {
        val subCommandParams = request.subCommandParams
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)

        val subCommandParamsBytes = ctapAuthenticatorSession.objectConverter.cborMapper
            .writeValueAsBytes(subCommandParams)
        val message = byteArrayOf(request.subCommand.value.toByte()) + subCommandParamsBytes
        verifyPinUvAuthParam(message, requireNoPermissionsRpId = false)

        val credentialID = subCommandParams.credentialID
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)

        val user = subCommandParams.user
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)

        val credential = findCredentialById(credentialID.id)
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_NO_CREDENTIALS)

        // If permissionsRpId is set, it must match the RP ID of the target credential
        val protocol = resolveProtocol()
        val tokenRpId = protocol.tokenState.permissionsRpId
        if (tokenRpId != null && tokenRpId != credential.rpId) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        // The user.id must match the existing credential's userHandle
        if (!user.id.contentEquals(credential.userHandle)) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
        }

        // Create updated credential with new user information
        val updatedCredential = ResidentUserCredential(
            credentialId = credential.credentialId,
            credentialKey = credential.credentialKey,
            userHandle = credential.userHandle,
            username = user.name,
            displayName = user.displayName,
            icon = credential.icon,
            rpId = credential.rpId,
            rpName = credential.rpName,
            rpIcon = credential.rpIcon,
            counter = credential.counter,
            createdAt = credential.createdAt,
            otherUI = credential.otherUI,
            details = credential.details
        )

        ctapAuthenticatorSession.authenticatorPropertyStore.saveUserCredential(updatedCredential)

        return AuthenticatorCredentialManagementResponse(CtapStatusCode.CTAP2_OK)
    }

    // ========================================================================
    // PIN/UV Auth Verification Helper
    // ========================================================================

    /**
     * Verifies the pinUvAuthParam against the given message.
     * Checks CM permission and optionally requires no permissionsRpId restriction.
     *
     * @param message the message to verify the pinUvAuthParam against
     * @param requireNoPermissionsRpId if true, permissionsRpId must be null
     */
    private fun verifyPinUvAuthParam(message: ByteArray, requireNoPermissionsRpId: Boolean) {
        val pinUvAuthParam = request.pinUvAuthParam
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PUAT_REQUIRED)

        // TODO: Support persistentPinUvAuthToken with pcmr permission for read-only operations (§6.8)

        val protocol = resolveProtocol()

        // Verify the pinUvAuthParam
        if (!protocol.verify(protocol.pinUvAuthToken, message, pinUvAuthParam)) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        // Check userVerifiedFlagValue
        if (!protocol.tokenState.getUserVerifiedFlagValue()) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        // Check CM permission
        if (!protocol.tokenState.hasPermission(PinUvAuthTokenPermission.CM)) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        // For some subcommands, permissionsRpId must be null (no RP ID restriction)
        if (requireNoPermissionsRpId && protocol.tokenState.permissionsRpId != null) {
            throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_PIN_AUTH_INVALID)
        }

        protocol.tokenState.recordTokenUsage()
    }

    /**
     * Resolve the PinUvAuthProtocol matching the request's pinUvAuthProtocol.
     */
    private fun resolveProtocol(): PinUvAuthProtocol {
        val pinUvAuthProtocol = request.pinUvAuthProtocol
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP2_ERR_MISSING_PARAMETER)

        return ctapAuthenticatorSession.pinUvAuthManager.pinUvAuthProtocols
            .firstOrNull { it.version == pinUvAuthProtocol }
            ?: throw CtapCommandExecutionException(CtapStatusCode.CTAP1_ERR_INVALID_PARAMETER)
    }

    // ========================================================================
    // Response Building Helpers
    // ========================================================================

    /**
     * Build response for an RP entry.
     */
    private fun buildRpResponse(rpId: String, totalRPs: UInt?): AuthenticatorCredentialManagementResponse {
        val rp = PublicKeyCredentialRpEntity(rpId, rpId)
        val rpIDHash = MessageDigestUtil.createSHA256().digest(rpId.toByteArray())

        val responseData = AuthenticatorCredentialManagementResponseData(
            existingResidentCredentialsCount = null,
            maxPossibleRemainingResidentCredentialsCount = null,
            rp = rp,
            rpIDHash = rpIDHash,
            totalRPs = totalRPs,
            user = null,
            credentialID = null,
            publicKey = null,
            totalCredentials = null,
            credProtect = null
        )
        return AuthenticatorCredentialManagementResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    /**
     * Build response for a credential entry.
     */
    private fun buildCredentialResponse(
        credential: ResidentUserCredential,
        totalCredentials: UInt?
    ): AuthenticatorCredentialManagementResponse {
        val user = PublicKeyCredentialUserEntity(
            credential.userHandle,
            credential.username ?: "",
            credential.displayName ?: ""
        )

        val credentialID = PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY,
            credential.credentialId,
            null
        )

        val publicKey = extractPublicCOSEKey(credential)

        // Extract credProtect value from credential details (default: level 1 = userVerificationOptional)
        val credProtect = credential.details["credProtect"]?.toUIntOrNull() ?: 1u

        val responseData = AuthenticatorCredentialManagementResponseData(
            existingResidentCredentialsCount = null,
            maxPossibleRemainingResidentCredentialsCount = null,
            rp = null,
            rpIDHash = null,
            totalRPs = null,
            user = user,
            credentialID = credentialID,
            publicKey = publicKey,
            totalCredentials = totalCredentials,
            credProtect = credProtect
        )
        return AuthenticatorCredentialManagementResponse(CtapStatusCode.CTAP2_OK, responseData)
    }

    /**
     * Extract the public COSEKey from a credential's key pair.
     */
    private fun extractPublicCOSEKey(credential: ResidentUserCredential): COSEKey {
        val keyPair = credential.credentialKey.keyPair
            ?: throw IllegalStateException("Credential key pair must not be null")
        val alg = credential.credentialKey.alg
            ?: throw IllegalStateException("Credential algorithm must not be null")
        val coseAlg = COSEAlgorithmIdentifier.create(alg)

        return when (val publicKey = keyPair.public) {
            is ECPublicKey -> EC2COSEKey.create(publicKey, coseAlg)
            is RSAPublicKey -> RSACOSEKey.create(publicKey, coseAlg)
            else -> throw IllegalArgumentException("Unsupported key type: ${keyPair.public.javaClass}")
        }
    }

    // ========================================================================
    // Credential Lookup Helper
    // ========================================================================

    /**
     * Find a resident credential by its credential ID across all RPs.
     */
    private fun findCredentialById(credentialId: ByteArray): ResidentUserCredential? {
        val allRpIds = ctapAuthenticatorSession.authenticatorPropertyStore.loadAllRpIds()
        for (rpId in allRpIds) {
            val credentials = ctapAuthenticatorSession.authenticatorPropertyStore.loadUserCredentials(rpId)
            val found = credentials.firstOrNull { it.credentialId.contentEquals(credentialId) }
            if (found != null) {
                return found
            }
        }
        return null
    }
}
