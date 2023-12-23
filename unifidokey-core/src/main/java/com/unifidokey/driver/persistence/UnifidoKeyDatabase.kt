package com.unifidokey.driver.persistence

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters
import com.unifidokey.driver.persistence.UnifidoKeyDatabase.Companion.DB_VERSION_1
import com.unifidokey.driver.persistence.converter.room.ByteArrayConverter
import com.unifidokey.driver.persistence.converter.room.DateConverter
import com.unifidokey.driver.persistence.converter.room.EventTypeConverter
import com.unifidokey.driver.persistence.converter.room.InstantConverter
import com.unifidokey.driver.persistence.converter.room.KeyPairConverter
import com.unifidokey.driver.persistence.converter.room.SignatureAlgorithmConverter
import com.unifidokey.driver.persistence.converter.room.UUIDConverter
import com.unifidokey.driver.persistence.dao.EventDao
import com.unifidokey.driver.persistence.dao.RelyingPartyDao
import com.unifidokey.driver.persistence.dao.UserCredentialDao
import com.unifidokey.driver.persistence.dto.SerializableConverter
import com.unifidokey.driver.persistence.entity.EventEntity
import com.unifidokey.driver.persistence.entity.RelyingPartyEntity
import com.unifidokey.driver.persistence.entity.UserCredentialEntity

@Database(
    entities = [RelyingPartyEntity::class, UserCredentialEntity::class, EventEntity::class],
    version = DB_VERSION_1,
    exportSchema = true
)
@TypeConverters(
    KeyPairConverter::class,
    SignatureAlgorithmConverter::class,
    DateConverter::class,
    ByteArrayConverter::class,
    InstantConverter::class,
    EventTypeConverter::class,
    SerializableConverter::class,
    UUIDConverter::class,
)
abstract class UnifidoKeyDatabase : RoomDatabase() {

    companion object {
        const val DB_VERSION_1 = 1

        fun createInstance(context: Context): UnifidoKeyDatabase {
            return Room.databaseBuilder(
                context,
                UnifidoKeyDatabase::class.java,
                "UnifidoKey"
            )
                .allowMainThreadQueries()
                .addMigrations(/**/)
                .build()
        }
    }

    abstract val relyingPartyDao: RelyingPartyDao
    abstract val userCredentialDao: UserCredentialDao
    abstract val eventDao: EventDao
}
