package com.unifidokey.driver.persistence

import androidx.room.Database
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.unifidokey.driver.persistence.converter.room.*
import com.unifidokey.driver.persistence.dao.EventDao
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.unifidokey.driver.persistence.dao.UserCredentialDao
import com.unifidokey.driver.persistence.dto.SerializableConverter
import com.unifidokey.driver.persistence.entity.EventEntity
import com.unifidokey.driver.persistence.entity.RelyingPartyEntity
import com.unifidokey.driver.persistence.entity.UserCredentialEntity

@Database(
    entities = [RelyingPartyEntity::class, UserCredentialEntity::class, EventEntity::class],
    version = 1,
    exportSchema = false
)
@TypeConverters(
    KeyPairConverter::class,
    SignatureAlgorithmConverter::class,
    DateConverter::class,
    ByteArrayConverter::class,
    InstantConverter::class,
    SerializableConverter::class,
    UUIDConverter::class,
    EventTypeConverter::class
)
abstract class UnifidoKeyDatabase : RoomDatabase() {
    abstract val relyingPartyDao: RelyingPartyDao
    abstract val userCredentialDao: UserCredentialDao
    abstract val eventDao: EventDao
}
