/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.webauthn4j.ctap.core.util.internal

import com.webauthn4j.util.exception.UnexpectedCheckedException
import java.security.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec

object CipherUtil {

    private const val ENCRYPTION_FAILED_MESSAGE = "Encryption failed by illegal argument."
    private const val DECRYPTION_FAILED_MESSAGE = "Decryption failed by illegal argument."

    fun encryptWithAESCBCNoPadding(
        data: ByteArray?,
        secretKey: SecretKey?,
        iv: ByteArray?
    ): ByteArray {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            val ivParameterSpec = IvParameterSpec(iv)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)
            cipher.doFinal(data)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw UnexpectedCheckedException(e)
        } catch (e: NoSuchPaddingException) {
            throw IllegalArgumentException(ENCRYPTION_FAILED_MESSAGE, e)
        } catch (e: InvalidKeyException) {
            throw IllegalArgumentException(ENCRYPTION_FAILED_MESSAGE, e)
        } catch (e: IllegalBlockSizeException) {
            throw IllegalArgumentException(ENCRYPTION_FAILED_MESSAGE, e)
        } catch (e: BadPaddingException) {
            throw IllegalArgumentException(ENCRYPTION_FAILED_MESSAGE, e)
        }
    }

    @JvmStatic
    fun encryptWithAESCBCPKCS5Padding(
        data: ByteArray?,
        secretKey: SecretKey?,
        iv: ByteArray?
    ): ByteArray {
        return try {
            val cipher: Cipher = if (isAndroidKeyStoreBCWorkaroundProviderAvailable) {
                Cipher.getInstance(
                    "AES/CBC/PKCS7Padding",
                    "AndroidKeyStoreBCWorkaround"
                ) // for Android
            } else {
                Cipher.getInstance("AES/CBC/PKCS5Padding") // for JDK without additional SecurityProvider
            }
            val ivParameterSpec = IvParameterSpec(iv)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)
            cipher.doFinal(data)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw UnexpectedCheckedException(e)
        } catch (e: NoSuchProviderException) {
            throw UnexpectedCheckedException(e)
        } catch (e: NoSuchPaddingException) {
            throw IllegalArgumentException(ENCRYPTION_FAILED_MESSAGE, e)
        } catch (e: InvalidKeyException) {
            throw IllegalArgumentException(ENCRYPTION_FAILED_MESSAGE, e)
        } catch (e: IllegalBlockSizeException) {
            throw IllegalArgumentException(ENCRYPTION_FAILED_MESSAGE, e)
        } catch (e: BadPaddingException) {
            throw IllegalArgumentException(ENCRYPTION_FAILED_MESSAGE, e)
        }
    }

    fun decryptWithAESCBCNoPadding(
        encrypted: ByteArray?,
        secretKey: SecretKey?,
        iv: ByteArray?
    ): ByteArray {
        return try {
            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            val ivParameterSpec = IvParameterSpec(iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)
            cipher.doFinal(encrypted)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw UnexpectedCheckedException(e)
        } catch (e: NoSuchPaddingException) {
            throw IllegalArgumentException(DECRYPTION_FAILED_MESSAGE, e)
        } catch (e: InvalidKeyException) {
            throw IllegalArgumentException(DECRYPTION_FAILED_MESSAGE, e)
        } catch (e: IllegalBlockSizeException) {
            throw IllegalArgumentException(DECRYPTION_FAILED_MESSAGE, e)
        } catch (e: BadPaddingException) {
            throw IllegalArgumentException(DECRYPTION_FAILED_MESSAGE, e)
        }
    }

    @SuppressWarnings("kotlin:S3776")
    @JvmStatic
    fun decryptWithAESCBCPKCS5Padding(
        encrypted: ByteArray?,
        secretKey: SecretKey?,
        iv: ByteArray?
    ): ByteArray? {
        return if (encrypted == null) {
            null
        } else try {
            val cipher: Cipher = if (isAndroidKeyStoreBCWorkaroundProviderAvailable) {
                Cipher.getInstance(
                    "AES/CBC/PKCS7Padding",
                    "AndroidKeyStoreBCWorkaround"
                ) // for Android
            } else {
                Cipher.getInstance("AES/CBC/PKCS5Padding") // for JDK without additional SecurityProvider
            }
            val ivParameterSpec = IvParameterSpec(iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec)
            cipher.doFinal(encrypted)
        } catch (e: NoSuchAlgorithmException) {
            throw UnexpectedCheckedException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw UnexpectedCheckedException(e)
        } catch (e: NoSuchProviderException) {
            throw UnexpectedCheckedException(e)
        } catch (e: NoSuchPaddingException) {
            throw IllegalArgumentException(DECRYPTION_FAILED_MESSAGE, e)
        } catch (e: InvalidKeyException) {
            throw IllegalArgumentException(DECRYPTION_FAILED_MESSAGE, e)
        } catch (e: IllegalBlockSizeException) {
            throw IllegalArgumentException(DECRYPTION_FAILED_MESSAGE, e)
        } catch (e: BadPaddingException) {
            throw IllegalArgumentException(DECRYPTION_FAILED_MESSAGE, e)
        }
    }

    private val isAndroidKeyStoreBCWorkaroundProviderAvailable: Boolean
        get() = Security.getProviders()
            .any { provider: Provider -> provider.name == "AndroidKeyStoreBCWorkaround" }
}