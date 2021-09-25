package com.unifidokey.driver.persistence

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.unifidokey.driver.persistence.UnifidoKeyDatabase.Companion.DB_VERSION_2
import com.unifidokey.driver.persistence.converter.room.*
import com.unifidokey.driver.persistence.dao.EventDao
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.unifidokey.driver.persistence.dao.UserCredentialDao
import com.unifidokey.driver.persistence.dto.SerializableConverter
import com.unifidokey.driver.persistence.entity.EventEntity
import com.unifidokey.driver.persistence.entity.RelyingPartyEntity
import com.unifidokey.driver.persistence.entity.UserCredentialEntity
import com.unifidokey.driver.persistence.migration.V1_2Migration

@Database(
    entities = [RelyingPartyEntity::class, UserCredentialEntity::class, EventEntity::class],
    version = DB_VERSION_2,
    exportSchema = true
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

    companion object{
        const val DB_VERSION_1 = 1
        const val DB_VERSION_2 = 2

        fun createInstance(context: Context): UnifidoKeyDatabase{
            return Room.databaseBuilder(
                context,
                UnifidoKeyDatabase::class.java,
                "UnifidoKey"
            )
                .allowMainThreadQueries()
                .addMigrations(V1_2Migration())
                .build()
        }
    }

    abstract val relyingPartyDao: RelyingPartyDao
    abstract val userCredentialDao: UserCredentialDao
    abstract val eventDao: EventDao
}
