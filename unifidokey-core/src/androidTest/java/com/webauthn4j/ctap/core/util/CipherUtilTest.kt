package com.webauthn4j.ctap.core.util

import com.google.common.truth.Truth
import com.unifidokey.driver.persistence.dao.AndroidKeyStoreDao
import com.webauthn4j.ctap.core.util.internal.CipherUtil
import org.junit.Before
import org.junit.Test

class CipherUtilTest {

    private lateinit var keyStoreDao: AndroidKeyStoreDao

    @Before
    fun setup() {
        keyStoreDao = AndroidKeyStoreDao()
    }

    @Test
    fun encrypt_test() {
        val original = ByteArray(32)
        val secretKey = keyStoreDao.findOrCreateEncryptionKey()
        val iv = ByteArray(16)
        CipherUtil.encryptWithAESCBCPKCS5Padding(original, secretKey, iv)
    }

    @Test
    fun decrypt_test() {
        val original = ByteArray(32)
        val secretKey = keyStoreDao.findOrCreateEncryptionKey()
        val iv = ByteArray(16)
        val encrypted = CipherUtil.encryptWithAESCBCPKCS5Padding(original, secretKey, iv)
        val decrypted = CipherUtil.decryptWithAESCBCPKCS5Padding(encrypted, secretKey, iv)
        Truth.assertThat(decrypted).isEqualTo(original)
    }
}