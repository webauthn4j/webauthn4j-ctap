package com.webauthn4j.ctap.authenticator.event

import com.fasterxml.jackson.annotation.JsonAnyGetter
import com.fasterxml.jackson.annotation.JsonAnySetter
import com.fasterxml.jackson.annotation.JsonIgnore
import java.time.Instant

abstract class EventBase(
    id: Long?,
    time: Instant,
    final override val type: EventType,
    leftover: Map<String, Any?>
) : Event {

    private var _map: HashMap<String, Any?> = HashMap(leftover)

    init {
        set("id", id)
        set("time", time)
        set("type", type)
    }

    override operator fun get(key: String): Any? {
        return _map[key]
    }

    protected operator fun set(key: String, value: Any?) {
        _map[key] = value
    }

    override val id: Long?
        @JsonIgnore
        get() = get("id") as Long?

    override val time: Instant
        @JsonIgnore
        get() = get("time") as Instant

    @Suppress("unused", "kotlin:S1144")
    @JsonAnyGetter
    private fun jsonAnyGetter(): Map<String, Any?> {
        return _map
    }

    @Suppress("unused", "kotlin:S1144")
    @JsonAnySetter
    private fun jsonAnySetter(key: String, value: Any?) {
        if (key != "type") {
            _map[key] = value
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EventBase) return false

        if (_map != other._map) return false

        return true
    }

    override fun hashCode(): Int {
        return _map.hashCode()
    }


}