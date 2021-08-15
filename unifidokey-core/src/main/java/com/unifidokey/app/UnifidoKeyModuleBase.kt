package com.unifidokey.app

import androidx.room.Room
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.unifidokey.core.adapter.UnifidoKeyAuthenticatorPropertyStore
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.service.AuthenticatorService
import com.unifidokey.core.service.BLEService
import com.unifidokey.core.service.BTHIDService
import com.unifidokey.core.service.NFCService
import com.unifidokey.driver.attestation.AndroidKeyAttestationStatementGenerator
import com.unifidokey.driver.attestation.AndroidSafetyNetAttestationStatementGenerator
import com.unifidokey.driver.persistence.UnifidoKeyAuthenticatorPropertyStoreImpl
import com.unifidokey.driver.persistence.UnifidoKeyDatabase
import com.unifidokey.driver.persistence.dao.*
import com.unifidokey.driver.transport.CtapBLEAndroidServiceContextualAdapter
import com.unifidokey.driver.transport.CtapBTHIDAndroidServiceContextualAdapter
import com.unifidokey.driver.transport.CtapNFCAndroidServiceAdapter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementGenerator
import com.webauthn4j.ctap.authenticator.attestation.FIDOU2FAttestationStatementGenerator
import com.webauthn4j.ctap.authenticator.attestation.NoneAttestationStatementGenerator
import com.webauthn4j.ctap.authenticator.attestation.PackedAttestationStatementGenerator
import com.webauthn4j.ctap.authenticator.settings.AttestationStatementFormatSetting
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import com.webauthn4j.ctap.core.converter.jackson.PublicKeyCredentialSourceCBORModule
import dagger.Module
import dagger.Provides
import java.util.*
import javax.inject.Named
import javax.inject.Singleton

/**
 * Defines Dagger2 configuration
 */
@Module
abstract class UnifidoKeyModuleBase<TA : UnifidoKeyApplicationBase<TC>, TC : UnifidoKeyComponent> {
    // CtapBLEAdaptor and CtapNFCAdaptor and it's holder like AuthenticatorService
    // must not be provided here as it must be created per Context
    @Singleton
    @Provides
    fun provideUnifidoKeyAuthenticatorService(
        authenticatorPropertyStore: UnifidoKeyAuthenticatorPropertyStore,
        configManager: ConfigManager,
        nfcService: NFCService,
        bleService: BLEService,
        bthidService: BTHIDService,
        eventDao: EventDao,
        androidKeyAttestationStatementGenerator: AndroidKeyAttestationStatementGenerator,
        androidSafetyNetAttestationStatementGenerator: AndroidSafetyNetAttestationStatementGenerator,
        packedAttestationStatementGenerator: PackedAttestationStatementGenerator,
        fidoU2FAttestationStatementGenerator: FIDOU2FAttestationStatementGenerator,
        objectConverter: ObjectConverter
    ): AuthenticatorService {
        val attestationStatementGenerators: MutableMap<AttestationStatementFormatSetting, AttestationStatementGenerator> =
            EnumMap(AttestationStatementFormatSetting::class.java)
        attestationStatementGenerators[AttestationStatementFormatSetting.ANDROID_KEY] =
            androidKeyAttestationStatementGenerator
        attestationStatementGenerators[AttestationStatementFormatSetting.ANDROID_SAFETYNET] =
            androidSafetyNetAttestationStatementGenerator
        attestationStatementGenerators[AttestationStatementFormatSetting.PACKED] =
            packedAttestationStatementGenerator
        attestationStatementGenerators[AttestationStatementFormatSetting.FIDO_U2F] =
            fidoU2FAttestationStatementGenerator
        attestationStatementGenerators[AttestationStatementFormatSetting.NONE] =
            NoneAttestationStatementGenerator()
        return AuthenticatorService(
            authenticatorPropertyStore,
            configManager,
            nfcService,
            bleService,
            bthidService,
            eventDao,
            attestationStatementGenerators,
            objectConverter
        )
    }

    @Singleton
    @Provides
    fun provideAndroidKeyAttestationStatementGenerator(objectConverter: ObjectConverter): AndroidKeyAttestationStatementGenerator {
        return AndroidKeyAttestationStatementGenerator(objectConverter)
    }

    @Singleton
    @Provides
    fun provideAndroidSafetyNetAttestationStatementGenerator(
        unifidoKeyApplication: TA,
        objectConverter: ObjectConverter,
        @Named("androidSafetyNetAPIKey") apiKey: String
    ): AndroidSafetyNetAttestationStatementGenerator {
        return AndroidSafetyNetAttestationStatementGenerator(
            apiKey,
            unifidoKeyApplication,
            objectConverter
        )
    }

    @Singleton
    @Provides
    fun providePackedAttestationStatementGenerator(): PackedAttestationStatementGenerator {
        return PackedAttestationStatementGenerator.createWithDemoAttestation() //TODO revisit
    }

    @Singleton
    @Provides
    fun provideFidoU2FAttestationStatementGenerator(): FIDOU2FAttestationStatementGenerator {
        return FIDOU2FAttestationStatementGenerator.createWithDemoAttestation()  //TODO revisit
    }

    @Singleton
    @Provides
    fun provideObjectConverter(): ObjectConverter {
        val jsonMapper = ObjectMapper()
        jsonMapper.registerModule(JavaTimeModule())
        val cborMapper = ObjectMapper(CBORFactory())
        cborMapper.registerModule(CtapCBORModule())
        cborMapper.registerModule(PublicKeyCredentialSourceCBORModule())
        cborMapper.registerModule(JavaTimeModule())
        return ObjectConverter(jsonMapper, cborMapper)
    }

    @Singleton
    @Provides
    fun provideAuthenticatorPropertyStore(
        userCredentialDao: UserCredentialDao,
        relyingPartyDao: RelyingPartyDao,
        configManager: ConfigManager,
        keyStoreDao: KeyStoreDao
    ): UnifidoKeyAuthenticatorPropertyStore {
        return UnifidoKeyAuthenticatorPropertyStoreImpl(
            relyingPartyDao,
            userCredentialDao,
            configManager,
            keyStoreDao
        )
    }

    @Singleton
    @Provides
    fun providePreferenceDao(unifidoKeyApplicationBase: TA): PreferenceDao {
        return PreferenceDao(unifidoKeyApplicationBase)
    }

    @Singleton
    @Provides
    fun provideKeyStoreDao(): KeyStoreDao {
        return AndroidKeyStoreDao()
    }

    @Singleton
    @Provides
    fun provideUnifidoKeyDatabase(unifidoKeyHandHeldApplication: TA): UnifidoKeyDatabase {
        return Room.databaseBuilder(
            unifidoKeyHandHeldApplication,
            UnifidoKeyDatabase::class.java,
            "UnifidoKey"
        )
            .allowMainThreadQueries()
            .build()
    }

    @Singleton
    @Provides
    fun provideRelyingPartyDao(UnifidoKeyDatabase: UnifidoKeyDatabase): RelyingPartyDao {
        return UnifidoKeyDatabase.relyingPartyDao
    }

    @Singleton
    @Provides
    fun provideUserCredentialDao(UnifidoKeyDatabase: UnifidoKeyDatabase): UserCredentialDao {
        return UnifidoKeyDatabase.userCredentialDao
    }

    @Singleton
    @Provides
    fun provideEventDao(UnifidoKeyDatabase: UnifidoKeyDatabase): EventDao {
        return UnifidoKeyDatabase.eventDao
    }

    @Singleton
    @Provides
    fun provideCtapNFCAndroidServiceAdapter(unifidoKeyHandHeldApplication: TA): CtapNFCAndroidServiceAdapter {
        return CtapNFCAndroidServiceAdapter(unifidoKeyHandHeldApplication)
    }

    @Singleton
    @Provides
    fun provideCtapBLEAndroidServiceContextualAdapter(unifidoKeyHandHeldApplication: TA): CtapBLEAndroidServiceContextualAdapter {
        return CtapBLEAndroidServiceContextualAdapter(unifidoKeyHandHeldApplication)
    }

    @Singleton
    @Provides
    fun provideCtapBTHIDAndroidServiceContextualAdapter(unifidoKeyHandHeldApplication: TA): CtapBTHIDAndroidServiceContextualAdapter {
        return CtapBTHIDAndroidServiceContextualAdapter(unifidoKeyHandHeldApplication)
    }

    @Singleton
    @Provides
    fun provideNFCService(
        configManager: ConfigManager,
        ctapNFCAndroidServiceAdapter: CtapNFCAndroidServiceAdapter
    ): NFCService {
        return NFCService(configManager, ctapNFCAndroidServiceAdapter)
    }

    @Singleton
    @Provides
    fun provideBLEService(
        configManager: ConfigManager,
        ctapBLEAndroidServiceContextualAdapter: CtapBLEAndroidServiceContextualAdapter
    ): BLEService {
        return BLEService(configManager, ctapBLEAndroidServiceContextualAdapter)
    }

    @Singleton
    @Provides
    fun provideBTHIDService(
        configManager: ConfigManager,
        ctapBTHIDAndroidServiceContextualAdapter: CtapBTHIDAndroidServiceContextualAdapter
    ): BTHIDService {
        return BTHIDService(configManager, ctapBTHIDAndroidServiceContextualAdapter)
    }
}