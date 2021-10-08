package com.unifidokey.driver.persistence.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import com.webauthn4j.ctap.authenticator.data.event.EventType
import java.time.Instant

@Entity(tableName = "event", indices = [Index(value = ["id"], unique = true)])
data class EventEntity(
    @field:PrimaryKey(autoGenerate = true) val id: Long?,
    @field:ColumnInfo(name = "time") val time: Instant,
    @field:ColumnInfo(name = "type") val type: EventType,
    @field:ColumnInfo(name = "details") val details: String
)
