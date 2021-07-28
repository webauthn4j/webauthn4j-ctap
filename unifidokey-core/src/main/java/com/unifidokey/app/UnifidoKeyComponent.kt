package com.unifidokey.app

import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.service.AuthenticatorService
import com.unifidokey.core.service.BLEService
import com.unifidokey.core.service.BTHIDService
import com.unifidokey.core.service.NFCService
import com.unifidokey.driver.notification.UnifidoKeyNotificationController
import com.unifidokey.driver.persistence.dao.EventDao
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.unifidokey.driver.persistence.dao.UserCredentialDao
import com.unifidokey.driver.transport.CtapBLEAndroidServiceContextualAdapter
import com.unifidokey.driver.transport.CtapBTHIDAndroidServiceContextualAdapter
import com.unifidokey.driver.transport.CtapNFCAndroidServiceAdapter
import com.webauthn4j.converter.util.ObjectConverter

interface UnifidoKeyComponent {
    val authenticatorService: AuthenticatorService
    val userCredentialDao: UserCredentialDao
    val relyingPartyDao: RelyingPartyDao
    val eventDao: EventDao
    val objectConverter: ObjectConverter
    val nfcServiceContextualAdapter: CtapNFCAndroidServiceAdapter
    val bleServiceContextualAdapter: CtapBLEAndroidServiceContextualAdapter
    val bthidServiceContextualAdapter: CtapBTHIDAndroidServiceContextualAdapter
    val bleService: BLEService
    val nfcService: NFCService
    val bthidService: BTHIDService
    val configManager: ConfigManager
    val unifidoKeyNotificationController: UnifidoKeyNotificationController
}