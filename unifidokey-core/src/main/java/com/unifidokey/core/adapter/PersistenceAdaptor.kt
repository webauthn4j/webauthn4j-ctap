package com.unifidokey.core.adapter

interface PersistenceAdaptor {
    operator fun contains(key: String): Boolean
    fun saveStringSet(key: String, value: Set<String>)
    fun loadStringSet(key: String): Set<String>
    fun saveString(key: String, value: String)
    fun loadString(key: String): String
    fun saveBoolean(key: String, value: Boolean?)
    fun loadBoolean(key: String): Boolean?
    fun savePrimitiveBoolean(key: String, value: Boolean)
    fun loadPrimitiveBoolean(key: String): Boolean
    fun savePrimitiveInt(key: String, value: Int)
    fun loadPrimitiveInt(key: String): Int
    fun saveBytes(key: String, value: ByteArray?)
    fun loadBytes(key: String): ByteArray?
}