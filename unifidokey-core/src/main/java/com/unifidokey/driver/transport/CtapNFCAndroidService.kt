package com.unifidokey.driver.transport

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import androidx.annotation.WorkerThread
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.core.service.NFCService
import com.unifidokey.core.service.NFCStatus
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCTransport
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import com.webauthn4j.ctap.core.exception.APDUProcessingException
import com.webauthn4j.ctap.core.util.internal.ArrayUtil
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import org.slf4j.LoggerFactory
import kotlin.coroutines.CoroutineContext

class CtapNFCAndroidService : HostApduService(), CoroutineScope {

    private val logger = LoggerFactory.getLogger(CtapNFCAndroidService::class.java)
    private lateinit var job: Job
    override val coroutineContext: CoroutineContext
        get() = job
    private lateinit var nfcTransport: NFCTransport
    private lateinit var nfcService: NFCService

    //single thread worker to synchronize authenticator access
    @OptIn(ExperimentalCoroutinesApi::class)
    private val nfcWorker = newSingleThreadContext("nfc-worker")

    @WorkerThread
    override fun onCreate() {
        super.onCreate()
        job = SupervisorJob()
        initialize()
    }

    @WorkerThread
    override fun onDestroy() {
        super.onDestroy()
        cancel()
    }

    @WorkerThread
    private fun initialize() {
        val unifidoKeyApplication = application as UnifidoKeyApplicationBase<*>
        val unifidoKeyComponent: UnifidoKeyComponent = unifidoKeyApplication.unifidoKeyComponent
        nfcTransport = unifidoKeyComponent.authenticatorService.nfcTransport
        nfcService = unifidoKeyComponent.nfcService
        logger.debug("CtapNFCAndroidService is initialized")
    }

    @WorkerThread
    override fun processCommandApdu(apdu: ByteArray, bundle: Bundle?): ByteArray? {
        launch(nfcWorker) {
            logger.debug("Received command APDU: {}", ArrayUtil.toHexString(apdu))
            if (nfcService.nfcStatus.value == NFCStatus.ON) {
                try {
                    val commandAPDU = CommandAPDU.parse(apdu)
                    val responseAPDU = nfcTransport.onCommandAPDUReceived(commandAPDU)
                    sendResponseApdu(responseAPDU.toBytes())
                    logger.debug(
                        "Sent response APDU: {}",
                        ArrayUtil.toHexString(responseAPDU.toBytes())
                    )
                } catch (e: APDUProcessingException) {
                    val responseAPDU = ResponseAPDU(e.statusCode.sw1, e.statusCode.sw2)
                    sendResponseApdu(responseAPDU.toBytes())
                    logger.debug(
                        "Sent response APDU: {}",
                        ArrayUtil.toHexString(responseAPDU.toBytes())
                    )
                }
            } else {
                val errorResponseAPDU = ResponseAPDU.createErrorResponseAPDU()
                sendResponseApdu(errorResponseAPDU.toBytes())
                logger.debug(
                    "Sent response APDU: {}",
                    ArrayUtil.toHexString(errorResponseAPDU.toBytes())
                )
            }
        }
        return null
    }

    @WorkerThread
    override fun onDeactivated(i: Int) {
        when (i) {
            DEACTIVATION_LINK_LOSS -> logger.debug("Deactivated by link loss")
            DEACTIVATION_DESELECTED -> logger.debug("Deactivated by other AID select")
            else -> throw IllegalStateException()
        }
    }
}