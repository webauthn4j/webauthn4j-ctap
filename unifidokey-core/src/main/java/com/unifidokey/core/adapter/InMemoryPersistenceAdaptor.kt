package com.unifidokey.core.adapter

import com.unifidokey.core.config.ConfigNotFoundException
import java.util.*

/**
 * In-memory [PersistenceAdaptor] for testing. Not for production-use.
 */
class InMemoryPersistenceAdaptor : PersistenceAdaptor {

    private val map: MutableMap<String, Any?> = HashMap()

    override fun contains(key: String): Boolean {
        return map.containsKey(key)
    }

    override fun saveStringSet(key: String, value: Set<String>) {
        saveValue(key, value)
    }

    override fun loadStringSet(key: String): Set<String> {
        return loadValue(key)
    }

    override fun saveString(key: String, value: String) {
        saveValue(key, value)
    }

    override fun loadString(key: String): String {
        return loadValue(key)
    }

    override fun saveBoolean(key: String, value: Boolean?) {
        saveValue(key, value)
    }

    override fun loadBoolean(key: String): Boolean? {
        return loadValue(key)
    }

    override fun savePrimitiveBoolean(key: String, value: Boolean) {
        saveValue(key, value)
    }

    override fun loadPrimitiveBoolean(key: String): Boolean {
        return loadValue(key)
    }

    override fun savePrimitiveInt(key: String, value: Int) {
        saveValue(key, value)
    }

    override fun loadPrimitiveInt(key: String): Int {
        return loadValue(key)
    }

    override fun saveBytes(key: String, value: ByteArray?) {
        saveValue(key, value)
    }

    override fun loadBytes(key: String): ByteArray? {
        return loadValue(key)
    }

    private fun saveValue(key: String, value: Any?) {
        map[key] = value
    }

    private fun <T> loadValue(key: String): T {
        return if (contains(key)) {
            @Suppress("UNCHECKED_CAST")
            map[key] as T
        } else {
            throw ConfigNotFoundException()
        }
    }
}
