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
            serializationContext.writeValue(generator, nonNullValue.value)
        }
        generator.writeEndObject()
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
