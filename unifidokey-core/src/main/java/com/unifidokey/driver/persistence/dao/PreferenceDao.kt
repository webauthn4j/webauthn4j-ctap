package com.unifidokey.driver.persistence.dao

import android.content.Context
import android.content.SharedPreferences
import androidx.preference.PreferenceManager
import com.unifidokey.core.adapter.PersistenceAdaptor
import com.unifidokey.core.config.ConfigNotFoundException
import com.webauthn4j.util.Base64Util

class PreferenceDao(context: Context) : PersistenceAdaptor {

    private val preferences: SharedPreferences =
        PreferenceManager.getDefaultSharedPreferences(context)

    override fun contains(key: String): Boolean {
        assertKey(key)
        return preferences.contains(getVersionKey(key))
    }

    override fun saveStringSet(key: String, value: Set<String>) {
        preferences.edit()
            .putInt(getVersionKey(key), PREFERENCE_DAO_VERSION)
            .putStringSet(key, value)
            .apply()
    }

    override fun loadStringSet(key: String): Set<String> {
        assertKey(key)
        return if (contains(key)) {
            preferences.getStringSet(key, null)!!
        } else {
            throw ConfigNotFoundException()
        }
    }

    override fun saveString(key: String, value: String) {
        assertKey(key)
        preferences.edit()
            .putInt(getVersionKey(key), PREFERENCE_DAO_VERSION)
            .putString(key, value)
            .apply()
    }

    override fun loadString(key: String): String {
        assertKey(key)
        return if (contains(key)) {
            preferences.getString(key, null)!!
        } else {
            throw ConfigNotFoundException()
        }
    }

    override fun saveBoolean(key: String, value: Boolean?) {
        assertKey(key)
        val string = when (value) {
            true -> "true"
            false -> "false"
            null -> "null"
        }
        preferences.edit()
            .putInt(getVersionKey(key), PREFERENCE_DAO_VERSION)
            .putString(key, string)
            .apply()
    }

    override fun loadBoolean(key: String): Boolean? {
        assertKey(key)
        if (contains(key)) {
            return when (preferences.getString(key, null)) {
                "true" -> true
                "false" -> false
                "null" -> null
                else -> null
            }
        } else {
            throw ConfigNotFoundException()
        }
    }

    override fun savePrimitiveBoolean(key: String, value: Boolean) {
        assertKey(key)
        preferences.edit()
            .putInt(getVersionKey(key), PREFERENCE_DAO_VERSION)
            .putBoolean(key, value)
            .apply()
    }

    override fun loadPrimitiveBoolean(key: String): Boolean {
        assertKey(key)
        return if (contains(key)) {
            preferences.getBoolean(key, false)
        } else {
            throw ConfigNotFoundException()
        }
    }

    override fun savePrimitiveInt(key: String, value: Int) {
        assertKey(key)
        preferences.edit()
            .putInt(getVersionKey(key), PREFERENCE_DAO_VERSION)
            .putInt(key, value)
            .apply()
    }

    override fun loadPrimitiveInt(key: String): Int {
        assertKey(key)
        return if (contains(key)) {
            preferences.getInt(key, 0)
        } else {
            throw ConfigNotFoundException()
        }
    }

    override fun saveBytes(key: String, value: ByteArray?) {
        assertKey(key)
        val base64Url = if (value == null) null else Base64Util.encodeToString(value)
        preferences.edit()
            .putInt(getVersionKey(key), PREFERENCE_DAO_VERSION)
            .putString(key, base64Url)
            .apply()
    }

    override fun loadBytes(key: String): ByteArray? {
        assertKey(key)
        return if (contains(key)) {
            val base64url = preferences.getString(key, null)
            if (base64url == null) null else Base64Util.decode(base64url)
        } else {
            throw ConfigNotFoundException()
        }
    }

    private fun assertKey(key: String) {
        require(!key.startsWith(METADATA_PREFIX)) {
            String.format(
                "key must not start with %s. It is reserved for metadata prefix.",
                METADATA_PREFIX
            )
        }
    }

    private fun getVersionKey(key: String): String {
        return METADATA_PREFIX + key + VERSION_SUFFIX
    }

    companion object {
        private const val METADATA_PREFIX = "metadata_"
        private const val VERSION_SUFFIX = "_version"
        private const val PREFERENCE_DAO_VERSION = 1
    }

}