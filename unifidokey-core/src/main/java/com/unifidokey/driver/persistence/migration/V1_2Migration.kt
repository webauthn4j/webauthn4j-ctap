package com.unifidokey.driver.persistence.migration

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import com.unifidokey.driver.persistence.UnifidoKeyDatabase

class V1_2Migration : Migration(UnifidoKeyDatabase.DB_VERSION_1, UnifidoKeyDatabase.DB_VERSION_2) {
    override fun migrate(database: SupportSQLiteDatabase) {
        //nop
    }
}