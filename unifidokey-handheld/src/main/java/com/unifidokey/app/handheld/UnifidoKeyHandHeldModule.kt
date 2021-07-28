package com.unifidokey.app.handheld

import com.unifidokey.BuildConfig
import com.unifidokey.app.UnifidoKeyModuleBase
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication.Companion.BLE_FEATURE_FLAG
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication.Companion.BTHID_FEATURE_FLAG
import com.unifidokey.app.handheld.UnifidoKeyHandHeldApplication.Companion.NFC_FEATURE_FLAG
import com.unifidokey.app.handheld.presentation.UnifidoKeyHandHeldNotificationController
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.driver.notification.UnifidoKeyNotificationController
import com.unifidokey.driver.persistence.dao.PreferenceDao
import dagger.Module
import dagger.Provides
import javax.inject.Named
import javax.inject.Singleton

@Module
class UnifidoKeyHandHeldModule(private val unifidoKeyHandHeldApplication: UnifidoKeyHandHeldApplication) :
    UnifidoKeyModuleBase<UnifidoKeyHandHeldApplication, UnifidoKeyHandHeldComponent>() {
    @Singleton
    @Provides
    fun provideUnifidoKeyApplication(): UnifidoKeyHandHeldApplication {
        return unifidoKeyHandHeldApplication
    }

    @Singleton
    @Provides
    @Named("androidSafetyNetAPIKey")
    fun provideAndroidSafetyNetAPIKey(): String {
        return BuildConfig.ANDROID_SAFETY_NET_API_KEY
    }

    @Singleton
    @Provides
    fun provideConfigurationService(preferenceDao: PreferenceDao): ConfigManager {
        return ConfigManager(
            preferenceDao,
            nfcFeatureFlag = NFC_FEATURE_FLAG,
            bleFeatureFlag = BLE_FEATURE_FLAG,
            bthidFeatureFlag = BTHID_FEATURE_FLAG
        )
    }

    @Singleton
    @Provides
    fun provideNotificationController(): UnifidoKeyNotificationController {
        return UnifidoKeyHandHeldNotificationController()
    }

}