/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.unifidokey.driver.converter.jackson

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.unifidokey.driver.converter.jackson.deserializer.json.ByteArraySerializer
import com.unifidokey.driver.converter.jackson.serializer.json.ByteArrayDeserializer

/**
 * A mix-in for [com.webauthn4j.data.PublicKeyCredentialUserEntity] not to fix
 * how to serialize it.
 */
abstract class PublicKeyCredentialUserEntityMixin @JsonCreator protected constructor(
    @JsonProperty("id") id: ByteArray,
    @JsonProperty("name") name: String,
    @JsonProperty("displayName") displayName: String
) {
    @get:JsonSerialize(using = ByteArraySerializer::class)
    @get:JsonDeserialize(using = ByteArrayDeserializer::class)
    abstract val id: String
}