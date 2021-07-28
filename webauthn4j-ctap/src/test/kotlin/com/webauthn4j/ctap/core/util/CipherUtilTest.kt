package com.webauthn4j.ctap.core.util

import com.webauthn4j.ctap.core.util.internal.CipherUtil
import com.webauthn4j.util.exception.UnexpectedCheckedException
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

internal class CipherUtilTest {
    private var secretKey: SecretKey? = null

    @BeforeEach
    fun setup() {
        secretKey = createSecretKey()
    }

    @Test
    fun encrypt_test() {
        val original = ByteArray(0)
        val iv = ByteArray(16)
        CipherUtil.encryptWithAESCBCPKCS5Padding(original, secretKey, iv)
    }

    @Test
    fun decrypt_test() {
        val original = ByteArray(0)
        val iv = ByteArray(16)
        val encrypted = CipherUtil.encryptWithAESCBCPKCS5Padding(original, secretKey, iv)
        val decrypted = CipherUtil.decryptWithAESCBCPKCS5Padding(encrypted, secretKey, iv)
        Assertions.assertThat(decrypted).isEqualTo(original)
    }

    private fun createSecretKey(): SecretKey {
        return try {
            val keyGenerator = KeyGenerator.getInstance("AES")
            val random = SecureRandom.getInstance("SHA1PRNG")
            keyGenerator.init(256, random)
            keyGenerator.generateKey()
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        }
    }
}