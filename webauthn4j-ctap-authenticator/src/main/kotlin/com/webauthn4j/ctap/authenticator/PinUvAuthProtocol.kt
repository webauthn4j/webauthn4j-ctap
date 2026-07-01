package com.webauthn4j.ctap.authenticator

import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.data.attestation.authenticator.COSEKey

// @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authnrClientPin-puaprot-abstract-dfn">6.5.4. PIN/UV Auth Protocol Abstract Definition</a>
//spec| A specific PIN/UV auth protocol defines an implementation of two interfaces to cryptographic services:
//spec| one for the authenticator, and one for the platform.
//spec| The authenticator interface is:
interface PinUvAuthProtocol {

    val version: PinProtocolVersion

    //spec| initialize()
    //spec|   This process is run by the authenticator at power-on.
    fun initialize()

    //spec| regenerate()
    //spec|   Generates a fresh public key.
    fun regenerate()

    //spec| resetPinUvAuthToken()
    //spec|   Generates a fresh pinUvAuthToken.
    fun resetPinUvAuthToken()

    //spec| getPublicKey() → coseKey
    //spec|   Returns the authenticator's public key as a COSE_Key structure.
    fun getPublicKey(): COSEKey

    //spec| decapsulate(peerCoseKey) → sharedSecret | error
    //spec|   Processes the output of encapsulate from the peer and produces a shared secret,
    //spec|   known to both the platform and the authenticator.
    fun decapsulate(peerCoseKey: COSEKey): ByteArray

    //spec| encrypt(key, demPlaintext) → ciphertext
    //spec|   Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext.
    //spec|   The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
    fun encrypt(key: ByteArray, plaintext: ByteArray): ByteArray

    //spec| decrypt(sharedSecret, ciphertext) → plaintext | error
    //spec|   Decrypts a ciphertext, using sharedSecret as a key, and returns the plaintext.
    fun decrypt(key: ByteArray, ciphertext: ByteArray): ByteArray

    //spec| authenticate(key, message) → signature
    //spec|   Computes a MAC of the given message.
    fun authenticate(key: ByteArray, message: ByteArray): ByteArray

    //spec| verify(key, message, signature) → success | error
    //spec|   Verifies that the signature is a valid MAC for the given message.
    //spec|   If the key parameter value is the current pinUvAuthToken, it also checks whether
    //spec|   the pinUvAuthToken is in use or not.
    fun verify(key: ByteArray, message: ByteArray, signature: ByteArray): Boolean

    val pinUvAuthToken: ByteArray
}
