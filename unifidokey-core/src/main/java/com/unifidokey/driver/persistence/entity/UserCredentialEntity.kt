package com.unifidokey.driver.persistence.entity

import androidx.room.*
import com.webauthn4j.data.SignatureAlgorithm
import java.io.Serializable
import java.security.KeyPair
import java.time.Instant

@Entity(
    tableName = "user_credential",
    foreignKeys = [ForeignKey(
        entity = RelyingPartyEntity::class,
        parentColumns = ["id"],
        childColumns = ["rp_id"],
        onDelete = ForeignKey.CASCADE
    )],
    indices = [Index(value = ["credential_id"], unique = true), Index(value = ["rp_id"])]
)
class UserCredentialEntity(
    @field:PrimaryKey(autoGenerate = true) val sid: Long?, //surrogate id
    @field:ColumnInfo(name = "credential_id") val credentialId: ByteArray,
    @field:ColumnInfo(name = "alg") val alg: SignatureAlgorithm,
    val keyPair: KeyPair?,
    val keyAlias: String?,
    @field:ColumnInfo(name = "user_handle") val userHandle: ByteArray,
    val username: String?,
    @field:ColumnInfo(name = "display_name") val displayName: String?,
    @field:ColumnInfo(name = "icon") val icon: String?,
    @field:ColumnInfo(name = "rp_id") val rpId: String,
    val counter: Long,
    @field:ColumnInfo(name = "created_at") val createdAt: Instant,
    @field:ColumnInfo(name = "other_ui") val otherUI: Serializable?,
    @field:ColumnInfo(name = "details") val details: String
) : Serializable {

    @Ignore
    constructor(
        credentialId: ByteArray,
        alg: SignatureAlgorithm,
        keyPair: KeyPair?,
        keyAlias: String?,
        userHandle: ByteArray,
        username: String?,
        displayName: String?,
        icon: String?,
        rpId: String,
        counter: Long,
        createdAt: Instant,
        otherUI: Serializable?,
        details: String
    ) : this(
        null,
        credentialId,
        alg,
        keyPair,
        keyAlias,
        userHandle,
        username,
        displayName,
        icon,
        rpId,
        counter,
        createdAt,
        otherUI,
        details
    )

    private fun equalsKeyPair(a: KeyPair?, b: KeyPair?): Boolean {
        return if (a != null && b != null) {
            a.private == b.private && a.public == b.public
        } else {
            a == b
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is UserCredentialEntity) return false

        if (sid != other.sid) return false
        if (!credentialId.contentEquals(other.credentialId)) return false
        if (alg != other.alg) return false
        if (keyPair != other.keyPair) return false
        if (keyAlias != other.keyAlias) return false
        if (!userHandle.contentEquals(other.userHandle)) return false
        if (username != other.username) return false
        if (displayName != other.displayName) return false
        if (icon != other.icon) return false
        if (rpId != other.rpId) return false
        if (counter != other.counter) return false
        if (createdAt != other.createdAt) return false
        if (otherUI != other.otherUI) return false
        if (details != other.details) return false

        return true
    }

    override fun hashCode(): Int {
        var result = sid?.hashCode() ?: 0
        result = 31 * result + credentialId.contentHashCode()
        result = 31 * result + alg.hashCode()
        result = 31 * result + (keyPair?.hashCode() ?: 0)
        result = 31 * result + (keyAlias?.hashCode() ?: 0)
        result = 31 * result + userHandle.contentHashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + displayName.hashCode()
        result = 31 * result + icon.hashCode()
        result = 31 * result + rpId.hashCode()
        result = 31 * result + counter.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + (otherUI?.hashCode() ?: 0)
        result = 31 * result + details.hashCode()
        return result
    }


}