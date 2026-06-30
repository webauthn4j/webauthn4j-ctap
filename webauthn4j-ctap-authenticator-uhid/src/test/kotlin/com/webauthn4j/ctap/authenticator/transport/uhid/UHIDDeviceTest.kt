package com.webauthn4j.ctap.authenticator.transport.uhid

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.hid.HIDResponseMessageBuilder
import com.webauthn4j.ctap.authenticator.transport.uhid.event.CreateDeviceEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.InputReportEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.OutputReportEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.event.UHIDEvent
import com.webauthn4j.ctap.authenticator.transport.uhid.UHIDConnection
import com.webauthn4j.ctap.core.converter.CtapRequestConverter
import com.webauthn4j.ctap.core.data.*
import com.webauthn4j.ctap.core.data.hid.*
import com.webauthn4j.ctap.core.data.hid.HIDMessage.Companion.DEFAULT_PACKET_SIZE
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import kotlinx.coroutines.*
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

internal class UHIDDeviceTest {

    private class FakeUHIDConnection : UHIDConnection() {
        val writtenEvents = ConcurrentLinkedQueue<UHIDEvent>()
        private val inputQueue = LinkedBlockingQueue<UHIDEvent>()
        @Volatile
        private var opened = false
        @Volatile
        private var closed = false

        override fun open() { opened = true }

        fun enqueueEvent(event: UHIDEvent) { inputQueue.put(event) }

        override fun readEvent(): UHIDEvent {
            while (!closed) {
                val event = inputQueue.poll(100, TimeUnit.MILLISECONDS)
                if (event != null) return event
            }
            throw java.io.IOException("Connection closed")
        }

        override fun writeEvent(event: UHIDEvent) {
            writtenEvents.add(event)
        }

        override val isOpen: Boolean get() = opened && !closed

        override fun close() { closed = true }
    }

    /**
     * Helper that handles UHID ↔ HID packet translation for tests.
     */
    private class TestHIDClient(private val connection: FakeUHIDConnection) {

        fun sendHIDPackets(packets: List<HIDPacket>) {
            for (packet in packets) {
                val packetBytes = packet.toBytes()
                connection.enqueueEvent(OutputReportEvent(packetBytes, packetBytes.size, 0x00))
            }
        }

        fun collectResponseHIDPackets(timeoutMs: Long = 2000): List<ByteArray> {
            val deadline = System.currentTimeMillis() + timeoutMs
            val packets = mutableListOf<ByteArray>()
            Thread.sleep(minOf(timeoutMs, 500))
            while (System.currentTimeMillis() < deadline) {
                val event = connection.writtenEvents.poll() ?: break
                if (event is InputReportEvent) {
                    packets.add(event.data)
                }
            }
            return packets
        }

        fun performCtapHIDInit(): HIDChannelId {
            val nonce = ByteArray(8) { (it + 1).toByte() }
            val initMessage = HIDINITRequestMessage(HIDChannelId.BROADCAST, nonce)
            sendHIDPackets(initMessage.toHIDPackets(DEFAULT_PACKET_SIZE))
            val responsePackets = collectResponseHIDPackets()
            assertThat(responsePackets).isNotEmpty()

            // Parse the INIT response to extract channel ID
            val hidPacket = responsePackets.first()
            // Channel ID is at bytes 15-18 of the INIT response data
            // Packet layout: CID(4) + CMD(1) + LEN(2) + DATA(...)
            // INIT response data: nonce(8) + channelId(4) + ...
            val channelIdBytes = hidPacket.copyOfRange(15, 19)
            return HIDChannelId(channelIdBytes)
        }

        fun sendCborCommand(channelId: HIDChannelId, ctapCommand: CtapCommand, cborData: ByteArray) {
            val message = HIDCBORRequestMessage(channelId, ctapCommand, cborData)
            sendHIDPackets(message.toHIDPackets(DEFAULT_PACKET_SIZE))
        }

        fun collectCborResponse(timeoutMs: Long = 3000): Pair<Byte, ByteArray> {
            val deadline = System.currentTimeMillis() + timeoutMs
            val builder = HIDResponseMessageBuilder()

            // Wait for processing to begin
            Thread.sleep(500)

            while (System.currentTimeMillis() < deadline) {
                val event = connection.writtenEvents.poll()
                if (event == null) {
                    Thread.sleep(50)
                    continue
                }

                if (event !is InputReportEvent) continue
                val packetBytes = event.data

                // Check if this is a keepalive (command 0xBB = KEEPALIVE | 0x80)
                if (packetBytes.size >= 5 && packetBytes[4] == (HIDCommand.CTAPHID_KEEPALIVE.value.toInt() or 0x80).toByte()) {
                    continue // Skip keepalive
                }

                // Parse HID packet
                val hidPacket = com.webauthn4j.ctap.core.converter.HIDPacketConverter().convert(packetBytes)
                when (hidPacket) {
                    is HIDInitializationPacket -> builder.initialize(hidPacket)
                    is HIDContinuationPacket -> builder.append(hidPacket)
                }

                if (builder.isCompleted) {
                    val message = builder.build()
                    val data = message.data
                    // data[0] = status code, data[1..] = CBOR response
                    val statusCode = data[0]
                    val cborResponse = if (data.size > 1) data.copyOfRange(1, data.size) else ByteArray(0)
                    return Pair(statusCode, cborResponse)
                }
            }
            throw AssertionError("Timed out waiting for CBOR response")
        }
    }

    private val objectConverter = ObjectConverter()
    private val ctapRequestConverter = CtapRequestConverter(objectConverter)

    @Test
    fun start_createsDevice() = runBlocking {
        val authenticator = CtapAuthenticator()
        val fakeConnection = FakeUHIDConnection()
        val bridge = UHIDDevice(authenticator, connection = fakeConnection)

        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        try {
            bridge.start(scope)
            delay(100)

            val createEvent = fakeConnection.writtenEvents.poll()
            assertThat(createEvent).isInstanceOf(CreateDeviceEvent::class.java)
        } finally {
            bridge.stop()
            scope.cancel()
        }
    }

    @Test
    fun ctaphidInit_returnsResponse() = runBlocking {
        val authenticator = CtapAuthenticator()
        val fakeConnection = FakeUHIDConnection()
        val bridge = UHIDDevice(authenticator, connection = fakeConnection)

        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        try {
            bridge.start(scope)
            delay(100)
            fakeConnection.writtenEvents.clear()

            val client = TestHIDClient(fakeConnection)
            val channelId = client.performCtapHIDInit()

            assertThat(channelId).isNotEqualTo(HIDChannelId.BROADCAST)
            assertThat(channelId.value).isNotEqualTo(ByteArray(4)) // Not all zeros
        } finally {
            bridge.stop()
            scope.cancel()
        }
    }

    @Test
    fun makeCredential_returnsSuccess() = runBlocking {
        val authenticator = CtapAuthenticator()
        val fakeConnection = FakeUHIDConnection()
        val bridge = UHIDDevice(authenticator, connection = fakeConnection)

        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        try {
            bridge.start(scope)
            delay(100)
            fakeConnection.writtenEvents.clear()

            val client = TestHIDClient(fakeConnection)

            // Step 1: CTAPHID_INIT to allocate a channel
            val channelId = client.performCtapHIDInit()

            // Step 2: Build MakeCredential request
            val request = AuthenticatorMakeCredentialRequest(
                clientDataHash = ByteArray(32),
                rp = CtapPublicKeyCredentialRpEntity("example.com", "Example", null),
                user = CtapPublicKeyCredentialUserEntity(
                    byteArrayOf(0x01, 0x02, 0x03), "user@example.com", "Test User", null
                ),
                pubKeyCredParams = listOf(
                    PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        COSEAlgorithmIdentifier.ES256
                    )
                ),
                excludeList = emptyList(),
                extensions = AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>(),
                options = AuthenticatorMakeCredentialRequest.Options(rk = false, uv = false),
                pinAuth = null,
                pinProtocol = null
            )
            val requestBytes = ctapRequestConverter.convertToBytes(request)
            val ctapCommandByte = requestBytes[0]
            val cborData = requestBytes.copyOfRange(1, requestBytes.size)

            // Step 3: Send CTAPHID_CBOR command
            client.sendCborCommand(channelId, CtapCommand(ctapCommandByte), cborData)

            // Step 4: Collect response
            val (statusCode, _) = client.collectCborResponse()

            // Step 5: Verify
            assertThat(statusCode).isEqualTo(CtapStatusCode.CTAP2_OK.byte)
        } finally {
            bridge.stop()
            scope.cancel()
        }
    }

    @Test
    fun getAssertion_afterMakeCredential_returnsSuccess() = runBlocking {
        val authenticator = CtapAuthenticator()
        val fakeConnection = FakeUHIDConnection()
        val bridge = UHIDDevice(authenticator, connection = fakeConnection)

        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        try {
            bridge.start(scope)
            delay(100)
            fakeConnection.writtenEvents.clear()

            val client = TestHIDClient(fakeConnection)
            val channelId = client.performCtapHIDInit()

            // -- MakeCredential --
            val rpId = "example.com"
            val makeCredRequest = AuthenticatorMakeCredentialRequest(
                clientDataHash = ByteArray(32),
                rp = CtapPublicKeyCredentialRpEntity(rpId, "Example", null),
                user = CtapPublicKeyCredentialUserEntity(
                    byteArrayOf(0x01, 0x02, 0x03), "user@example.com", "Test User", null
                ),
                pubKeyCredParams = listOf(
                    PublicKeyCredentialParameters(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        COSEAlgorithmIdentifier.ES256
                    )
                ),
                excludeList = emptyList(),
                extensions = AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>(),
                options = AuthenticatorMakeCredentialRequest.Options(rk = true, uv = false),
                pinAuth = null,
                pinProtocol = null
            )
            val makeCredBytes = ctapRequestConverter.convertToBytes(makeCredRequest)
            client.sendCborCommand(channelId, CtapCommand(makeCredBytes[0]), makeCredBytes.copyOfRange(1, makeCredBytes.size))
            val (makeCredStatus, _) = client.collectCborResponse()
            assertThat(makeCredStatus).isEqualTo(CtapStatusCode.CTAP2_OK.byte)

            // -- GetAssertion --
            val getAssertionRequest = AuthenticatorGetAssertionRequest(
                rpId = rpId,
                clientDataHash = ByteArray(32),
                allowList = emptyList(),
                extensions = null,
                options = AuthenticatorGetAssertionRequest.Options(up = true, uv = false),
                pinAuth = null,
                pinProtocol = null
            )
            val getAssertionBytes = ctapRequestConverter.convertToBytes(getAssertionRequest)
            client.sendCborCommand(channelId, CtapCommand(getAssertionBytes[0]), getAssertionBytes.copyOfRange(1, getAssertionBytes.size))
            val (getAssertionStatus, _) = client.collectCborResponse()
            assertThat(getAssertionStatus).isEqualTo(CtapStatusCode.CTAP2_OK.byte)
        } finally {
            bridge.stop()
            scope.cancel()
        }
    }
}
