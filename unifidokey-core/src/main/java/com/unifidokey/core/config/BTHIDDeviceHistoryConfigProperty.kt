package com.unifidokey.core.config

import com.fasterxml.jackson.core.type.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule
import com.webauthn4j.converter.util.JsonConverter
import com.webauthn4j.converter.util.ObjectConverter

class BTHIDDeviceHistoryConfigProperty internal constructor(configManager: ConfigManager) :
    ConfigPropertyBase<List<BTHIDDeviceHistoryEntry>?>(configManager, KEY, null, true, false, false) {

    companion object {
        const val KEY = "bthidDeviceHistory"
    }

    private val jsonConverter: JsonConverter

    init {
        val jsonMapper = ObjectMapper()
        jsonMapper.registerModule(JavaTimeModule())
        val cborMapper = ObjectMapper(CBORFactory())
        jsonConverter = ObjectConverter(jsonMapper, cborMapper).jsonConverter
    }

    override fun save(value: List<BTHIDDeviceHistoryEntry>?) {
        val json = jsonConverter.writeValueAsString(value)
        configManager.persistenceAdaptor.saveString(KEY, json)
    }

    @Throws(ConfigNotFoundException::class)
    override fun load(): List<BTHIDDeviceHistoryEntry>? {
        val json = configManager.persistenceAdaptor.loadString(KEY)
        return jsonConverter.readValue(
            json,
            object : TypeReference<List<BTHIDDeviceHistoryEntry>?>() {})
    }

}