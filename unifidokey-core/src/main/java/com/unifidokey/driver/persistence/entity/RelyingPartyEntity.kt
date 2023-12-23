package com.unifidokey.driver.persistence.entity

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.Ignore
import androidx.room.Index
import androidx.room.PrimaryKey
import java.io.Serializable

@Entity(tableName = "relying_party", indices = [Index(value = ["id"], unique = true)])
data class RelyingPartyEntity(
    @field:PrimaryKey(autoGenerate = true) val sid: Long?, // surrogate id
    val id: String, // rpId
    @field:ColumnInfo val name: String?,
    @field:ColumnInfo val icon: String?,
    @field:ColumnInfo(name= "biometric_authentication") val biometricAuthentication: Boolean,
) : Serializable {

    @Ignore
    constructor(id: String, name: String?, icon: String?, biometricAuthentication: Boolean) : this(null, id, name, icon, biometricAuthentication)

}