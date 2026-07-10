package com.webauthn4j.ctap.authenticator.extension

import com.webauthn4j.ctap.authenticator.data.credential.Credential
import com.webauthn4j.ctap.authenticator.data.credential.CredentialKey
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.extension.CredentialProtectionPolicy
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.mockito.Mockito.mock
import java.time.Instant

internal class CredProtectExtensionProcessorTest {

    private val processor = CredProtectExtensionProcessor()

    private fun credentialWithPolicy(policy: CredentialProtectionPolicy?): Credential {
        val details = if (policy != null) {
            mapOf("credProtect" to policy.toByte().toString())
        } else {
            emptyMap()
        }
        return object : Credential {
            override val credentialId = byteArrayOf(0x01)
            override val rpIdHash = byteArrayOf()
            override val credentialKey = mock(CredentialKey::class.java)
            override val counter = 0L
            override val createdAt: Instant = Instant.now()
            override val details = details
            override val isResidentKey = true
        }
    }

    private val allowList = listOf(
        PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, byteArrayOf(0x01), null)
    )

    private fun getAssertionContext(
        policy: CredentialProtectionPolicy?,
        uvResult: Boolean,
        allowList: List<PublicKeyCredentialDescriptor>?
    ): GetAssertionCredentialFilterContext {
        val request = mock(AuthenticatorGetAssertionRequest::class.java)
        org.mockito.Mockito.`when`(request.allowList).thenReturn(allowList)
        return GetAssertionCredentialFilterContext(request, credentialWithPolicy(policy), uvResult)
    }

    private fun makeCredentialContext(
        policy: CredentialProtectionPolicy?,
        uvResult: Boolean
    ): MakeCredentialCredentialFilterContext {
        val request = mock(AuthenticatorMakeCredentialRequest::class.java)
        return MakeCredentialCredentialFilterContext(request, credentialWithPolicy(policy), uvResult)
    }

    // §6.2.2 Step 7.4/7.5 — GetAssertion credential filtering
    @Nested
    inner class GetAssertionFilterTest {

        // §12.1 userVerificationOptional (0x01): default, always visible
        @Test
        fun level1_always_visible() {
            assertThat(processor.test(getAssertionContext(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL, uvResult = false, allowList = null))).isTrue()
            assertThat(processor.test(getAssertionContext(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL, uvResult = false, allowList = allowList))).isTrue()
            assertThat(processor.test(getAssertionContext(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL, uvResult = true, allowList = null))).isTrue()
        }

        // §12.1 userVerificationOptionalWithCredentialIDList (0x02):
        //spec| 7.5 ...if credential protection for a credential is marked as
        //spec| userVerificationOptionalWithCredentialIDList and there is no allowList passed
        //spec| by the client and the "uv" bit is false in the response,
        //spec| remove that credential from the applicable credentials list.
        @Test
        fun level2_no_allowList_no_uv_hidden() {
            assertThat(processor.test(getAssertionContext(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST, uvResult = false, allowList = null))).isFalse()
        }

        @Test
        fun level2_with_allowList_no_uv_visible() {
            assertThat(processor.test(getAssertionContext(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST, uvResult = false, allowList = allowList))).isTrue()
        }

        @Test
        fun level2_no_allowList_with_uv_visible() {
            assertThat(processor.test(getAssertionContext(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST, uvResult = true, allowList = null))).isTrue()
        }

        // §12.1 userVerificationRequired (0x03):
        //spec| 7.4 ...if credential protection for a credential is marked as
        //spec| userVerificationRequired, and the "uv" bit is false in the response,
        //spec| remove that credential from the applicable credentials list.
        @Test
        fun level3_no_uv_hidden() {
            assertThat(processor.test(getAssertionContext(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED, uvResult = false, allowList = null))).isFalse()
            assertThat(processor.test(getAssertionContext(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED, uvResult = false, allowList = allowList))).isFalse()
        }

        @Test
        fun level3_with_uv_visible() {
            assertThat(processor.test(getAssertionContext(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED, uvResult = true, allowList = null))).isTrue()
        }

        // Default when credProtect is not set — same as Level 1
        @Test
        fun no_policy_defaults_to_level1_always_visible() {
            assertThat(processor.test(getAssertionContext(null, uvResult = false, allowList = null))).isTrue()
        }
    }

    // §6.1.2 Step 12 — MakeCredential excludeList filtering
    @Nested
    inner class MakeCredentialFilterTest {

        // Level 1: always visible for excludeList matching
        @Test
        fun level1_always_visible() {
            assertThat(processor.test(makeCredentialContext(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL, uvResult = false))).isTrue()
        }

        // Level 2: always visible for excludeList matching
        @Test
        fun level2_always_visible() {
            assertThat(processor.test(makeCredentialContext(CredentialProtectionPolicy.USER_VERIFICATION_OPTIONAL_WITH_CREDENTIAL_ID_LIST, uvResult = false))).isTrue()
        }

        //spec| 12.2 Else (implying the credential's credProtect value is userVerificationRequired):
        //spec|   12.2.2 Else (implying user verification was not collected in Step 11), remove the credential from
        //spec|   the excludeList and continue parsing the rest of the list.
        @Test
        fun level3_no_uv_hidden() {
            assertThat(processor.test(makeCredentialContext(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED, uvResult = false))).isFalse()
        }

        //spec| 12.2.1 If the "uv" bit is true in the response:
        @Test
        fun level3_with_uv_visible() {
            assertThat(processor.test(makeCredentialContext(CredentialProtectionPolicy.USER_VERIFICATION_REQUIRED, uvResult = true))).isTrue()
        }

        // Default when credProtect is not set — same as Level 1
        @Test
        fun no_policy_defaults_to_level1_always_visible() {
            assertThat(processor.test(makeCredentialContext(null, uvResult = false))).isTrue()
        }
    }
}
