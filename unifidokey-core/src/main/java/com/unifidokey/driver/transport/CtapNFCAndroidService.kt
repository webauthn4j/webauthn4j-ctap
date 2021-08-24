package com.unifidokey.driver.transport

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import androidx.annotation.WorkerThread
import com.google.android.gms.common.util.concurrent.NamedThreadFactory
import com.unifidokey.app.UnifidoKeyApplicationBase
import com.unifidokey.app.UnifidoKeyComponent
import com.unifidokey.core.service.NFCService
import com.unifidokey.core.service.NFCStatus
import com.webauthn4j.ctap.authenticator.transport.nfc.NFCConnector
import com.webauthn4j.ctap.core.data.nfc.CommandAPDU
import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU
import com.webauthn4j.ctap.core.util.internal.ArrayUtil
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import java.util.concurrent.Executors
import kotlin.coroutines.CoroutineContext

class CtapNFCAndroidService : HostApduService(), CoroutineScope {

    private val logger = LoggerFactory.getLogger(CtapNFCAndroidService::class.java)
    private lateinit var job: Job
    override val coroutineContext: CoroutineContext
        get() = job
    private lateinit var nfcConnector: NFCConnector
    private lateinit var nfcService: NFCService

    //single thread worker to synchronize authenticator access
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
        val authenticatorService = unifidoKeyComponent.authenticatorService
        val objectConverter = unifidoKeyComponent.objectConverter
        nfcConnector = NFCConnector(authenticatorService, objectConverter)
        nfcService = unifidoKeyComponent.nfcService
        logger.debug("CtapNFCAndroidService is initialized")
    }

    @WorkerThread
    override fun processCommandApdu(apdu: ByteArray, bundle: Bundle?): ByteArray? {
        launch(nfcWorker) {
            logger.debug("Received command APDU: {}", ArrayUtil.toHexString(apdu))
            if (nfcService.nfcStatus.value == NFCStatus.ON) {
                val commandAPDU = CommandAPDU.parse(apdu)
                val responseAPDU = nfcConnector.handleCommandAPDU(commandAPDU)
                sendResponseApdu(responseAPDU.toBytes())
                logger.debug("Sent response APDU: {}", ArrayUtil.toHexString(responseAPDU.toBytes()))
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