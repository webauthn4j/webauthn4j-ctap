package com.unifidokey.driver.persistence.entity

import androidx.room.*
import java.io.Serializable

@Entity(tableName = "relying_party", indices = [Index(value = ["id"], unique = true)])
data class RelyingPartyEntity(
    @field:PrimaryKey(autoGenerate = true) val sid: Long?, // surrogate id
    val id: String, // rpId
    @field:ColumnInfo val name: String?,
    @field:ColumnInfo val icon: String?
) : Serializable {

    @Ignore
    constructor(id: String, name: String?, icon: String?) : this(null, id, name, icon)

}