package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.databind.SerializerProvider
import com.fasterxml.jackson.databind.ser.std.StdSerializer
import com.fasterxml.jackson.dataformat.cbor.CBORGenerator
import java.io.IOException
import java.util.function.Function

abstract class AbstractCtapCanonicalCborSerializer<T>(
    t: Class<T>,
    private val rules: List<FieldSerializationRule<T>>
) : StdSerializer<T>(t) {

    @Throws(IOException::class)
    override fun serialize(value: T, gen: JsonGenerator, provider: SerializerProvider) {
        val nonNullValues = rules
            .map { rule: FieldSerializationRule<T> ->
                val fieldValue = rule.getter.apply(value)
                KeyValue(rule.name, fieldValue)
            }
            .filter { it.value != null }
        (gen as CBORGenerator).writeStartObject(nonNullValues.size) // This is important to write finite length map
        for (nonNullValue in nonNullValues) {
            when (nonNullValue.name) {
                is String -> {
                    gen.writeFieldName(nonNullValue.name)
                }
                is Int -> {
                    gen.writeFieldId(nonNullValue.name.toLong())
                }
                else -> throw IllegalStateException("Unexpected field type")
            }
            gen.writeObject(nonNullValue.value)
        }
        gen.writeEndObject()
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