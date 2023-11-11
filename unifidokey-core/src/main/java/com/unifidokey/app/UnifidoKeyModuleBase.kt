package com.unifidokey.app

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.cfg.CoercionAction
import com.fasterxml.jackson.databind.cfg.CoercionInputShape
import com.fasterxml.jackson.databind.type.LogicalType
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.fasterxml.jackson.module.kotlin.KotlinModule
import com.unifidokey.core.adapter.UnifidoKeyAuthenticatorPropertyStore
import com.unifidokey.core.config.ConfigManager
import com.unifidokey.core.service.AuthenticatorService
import com.unifidokey.core.service.BLEService
import com.unifidokey.core.service.BTHIDService
import com.unifidokey.core.service.NFCService
import com.unifidokey.driver.attestation.AndroidKeyAttestationStatementProvider
import com.unifidokey.driver.attestation.AndroidSafetyNetAttestationStatementProvider
import com.unifidokey.driver.converter.jackson.Base64UrlRepresentationModule
import com.unifidokey.driver.persistence.UnifidoKeyAuthenticatorPropertyStoreImpl
import com.unifidokey.driver.persistence.UnifidoKeyDatabase
import com.unifidokey.driver.persistence.dao.*
import com.unifidokey.driver.transport.CtapBLEAndroidServiceContextualAdapter
import com.unifidokey.driver.transport.CtapBTHIDAndroidServiceContextualAdapter
import com.unifidokey.driver.transport.CtapNFCAndroidServiceAdapter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.ExceptionReporter
import com.webauthn4j.ctap.authenticator.attestation.*
import com.webauthn4j.ctap.authenticator.data.settings.AttestationStatementFormatSetting
import com.webauthn4j.ctap.authenticator.data.settings.AttestationTypeSetting
import com.webauthn4j.ctap.core.converter.jackson.CtapCBORModule
import com.webauthn4j.ctap.core.converter.jackson.PublicKeyCredentialSourceCBORModule
import dagger.Module
import dagger.Provides
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
        androidKeyAttestationStatementGenerator: AndroidKeyAttestationStatementProvider,
        androidSafetyNetAttestationStatementGenerator: AndroidSafetyNetAttestationStatementProvider,
        packedBasicAttestationStatementGenerator: PackedBasicAttestationStatementProvider,
        packedSelfAttestationStatementProvider: PackedSelfAttestationStatementProvider,
        fidoU2FBasicAttestationStatementGenerator: FIDOU2FBasicAttestationStatementProvider,
        fidoU2FSelfAttestationStatementProvider: FIDOU2FSelfAttestationStatementProvider,
        exceptionReporter: ExceptionReporter,
        objectConverter: ObjectConverter
    ): AuthenticatorService {
        val attestationStatementGenerators: MutableMap<Pair<AttestationTypeSetting, AttestationStatementFormatSetting>, AttestationStatementProvider> =
            HashMap()
        attestationStatementGenerators[Pair(
            AttestationTypeSetting.BASIC,
            AttestationStatementFormatSetting.ANDROID_KEY
        )] = androidKeyAttestationStatementGenerator
        attestationStatementGenerators[Pair(
            AttestationTypeSetting.BASIC,
            AttestationStatementFormatSetting.ANDROID_SAFETYNET
        )] = androidSafetyNetAttestationStatementGenerator
        attestationStatementGenerators[Pair(
            AttestationTypeSetting.BASIC,
            AttestationStatementFormatSetting.PACKED
        )] = packedBasicAttestationStatementGenerator
        attestationStatementGenerators[Pair(
            AttestationTypeSetting.SELF,
            AttestationStatementFormatSetting.PACKED
        )] = packedSelfAttestationStatementProvider
        attestationStatementGenerators[Pair(
            AttestationTypeSetting.BASIC,
            AttestationStatementFormatSetting.FIDO_U2F
        )] = fidoU2FBasicAttestationStatementGenerator
        attestationStatementGenerators[Pair(
            AttestationTypeSetting.SELF,
            AttestationStatementFormatSetting.FIDO_U2F
        )] = fidoU2FSelfAttestationStatementProvider
        attestationStatementGenerators[Pair(
            AttestationTypeSetting.BASIC,
            AttestationStatementFormatSetting.NONE
        )] = NoneAttestationStatementProvider()
        return AuthenticatorService(
            authenticatorPropertyStore,
            configManager,
            nfcService,
            bleService,
            bthidService,
            eventDao,
            attestationStatementGenerators,
            exceptionReporter,
            objectConverter
        )
    }

    @Singleton
    @Provides
    fun provideAndroidKeyAttestationStatementGenerator(objectConverter: ObjectConverter): AndroidKeyAttestationStatementProvider {
        return AndroidKeyAttestationStatementProvider(objectConverter)
    }

    @Singleton
    @Provides
    fun provideAndroidSafetyNetAttestationStatementGenerator(
        unifidoKeyApplication: TA,
        objectConverter: ObjectConverter,
        @Named("androidSafetyNetAPIKey") apiKey: String
    ): AndroidSafetyNetAttestationStatementProvider {
        return AndroidSafetyNetAttestationStatementProvider(
            apiKey,
            unifidoKeyApplication,
            objectConverter
        )
    }

    @Singleton
    @Provides
    fun providePackedBasicAttestationStatementGenerator(): PackedBasicAttestationStatementProvider {
        return PackedBasicAttestationStatementProvider.createWithDemoAttestationKey() //TODO revisit
    }

    @Singleton
    @Provides
    fun providePackedSelfAttestationStatementGenerator(objectConverter: ObjectConverter): PackedSelfAttestationStatementProvider {
        return PackedSelfAttestationStatementProvider(
            DemoAttestationConstants.DEMO_ATTESTATION_NAME,
            objectConverter
        )
    }

    @Singleton
    @Provides
    fun provideFidoU2FBasicAttestationStatementGenerator(): FIDOU2FBasicAttestationStatementProvider {
        return FIDOU2FBasicAttestationStatementProvider.createWithDemoAttestationKey()  //TODO revisit
    }

    @Singleton
    @Provides
    fun provideFidoU2FSelfAttestationStatementGenerator(): FIDOU2FSelfAttestationStatementProvider {
        return FIDOU2FSelfAttestationStatementProvider(DemoAttestationConstants.DEMO_ATTESTATION_NAME)
    }

    @Singleton
    @Provides
    fun provideObjectConverter(): ObjectConverter {
        val jsonMapper = ObjectMapper()
        jsonMapper.registerModule(JavaTimeModule())
        jsonMapper.registerModule(Base64UrlRepresentationModule())
        val cborMapper = ObjectMapper(CBORFactory())
        cborMapper.coercionConfigFor(LogicalType.Textual)
            .setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail)
        cborMapper.coercionConfigFor(LogicalType.Binary)
            .setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail)
        cborMapper.coercionConfigFor(LogicalType.Binary)
            .setCoercion(CoercionInputShape.String, CoercionAction.Fail)
        cborMapper.coercionConfigFor(LogicalType.Binary)
            .setCoercion(CoercionInputShape.Array, CoercionAction.Fail)
        cborMapper.coercionConfigFor(LogicalType.Binary)
            .setCoercion(CoercionInputShape.EmptyArray, CoercionAction.Fail)
        cborMapper.coercionConfigFor(LogicalType.Binary)
            .setCoercion(CoercionInputShape.EmptyObject, CoercionAction.Fail)
        cborMapper.coercionConfigFor(LogicalType.Binary)
            .setCoercion(CoercionInputShape.EmptyString, CoercionAction.Fail)
        cborMapper.coercionConfigFor(LogicalType.Binary)
            .setCoercion(CoercionInputShape.Float, CoercionAction.Fail)
        cborMapper.coercionConfigFor(LogicalType.Binary)
            .setCoercion(CoercionInputShape.Integer, CoercionAction.Fail)
        cborMapper.coercionConfigFor(LogicalType.Binary)
            .setCoercion(CoercionInputShape.Object, CoercionAction.Fail)
        cborMapper.registerModule(CtapCBORModule())
        cborMapper.registerModule(PublicKeyCredentialSourceCBORModule())
        cborMapper.registerModule(JavaTimeModule())
        cborMapper.registerModule(KotlinModule.Builder().build())
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
        return UnifidoKeyDatabase.createInstance(unifidoKeyHandHeldApplication)
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