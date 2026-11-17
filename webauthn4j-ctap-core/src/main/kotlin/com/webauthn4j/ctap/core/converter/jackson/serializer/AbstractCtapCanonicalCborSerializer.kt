package com.webauthn4j.ctap.core.converter.jackson.serializer

import tools.jackson.core.JsonGenerator
import tools.jackson.databind.SerializationContext
import tools.jackson.databind.ser.std.StdSerializer
import tools.jackson.dataformat.cbor.CBORGenerator
import java.util.function.Function

abstract class AbstractCtapCanonicalCborSerializer<T>(
    t: Class<T>,
    private val rules: List<FieldSerializationRule<T>>
) : StdSerializer<T>(t) {

    override fun serialize(value: T, generator: JsonGenerator, serializationContext: SerializationContext) {
        val nonNullValues = rules
            .map { rule: FieldSerializationRule<T> ->
                val fieldValue = rule.getter.apply(value)
                KeyValue(rule.name, fieldValue)
            }
            .filter { it.value != null }
        (generator as CBORGenerator).writeStartObject(value, nonNullValues.size) // This is important to write finite length map
        for (nonNullValue in nonNullValues) {
            when (nonNullValue.name) {
                is String -> {
                    generator.writeName(nonNullValue.name)
                }
                is Int -> {
                    (generator as CBORGenerator).writePropertyId(nonNullValue.name.toLong())
                }
                else -> throw IllegalStateException("Unexpected field type")
            }
            writeFieldValue(generator, serializationContext, nonNullValue.value)
        }
        generator.writeEndObject()
    }

    // Jackson's generic Map serializer emits indefinite-length CBOR maps.
    // Extension outputs must use definite lengths too, including nested maps.
    private fun writeFieldValue(generator: CBORGenerator, context: SerializationContext, value: Any?) {
        if (value is Map<*, *> && value.keys.all { it is String }) {
            val entries = value.entries.sortedWith(compareBy({ (it.key as String).toByteArray(Charsets.UTF_8).size }, { it.key as String }))
            generator.writeStartObject(value, entries.size)
            for ((key, item) in entries) {
                generator.writeName(key as String)
                writeFieldValue(generator, context, item)
            }
            generator.writeEndObject()
        } else {
            context.writeValue(generator, value)
        }
    }

    private class KeyValue(val name: Any, val value: Any?)

    class FieldSerializationRule<T> {
        val name: Any
        val getter: Function<T, *>

        constructor(name: Int, getter: Function<T, *>) {
            this.name = name
            this.getter = getter
        }

        constructor(name: String, getter: Function<T, *>) {
            this.name = name
            this.getter = getter
        }
    }
}
