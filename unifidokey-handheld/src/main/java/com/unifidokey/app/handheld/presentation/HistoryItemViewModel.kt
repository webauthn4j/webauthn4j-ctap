package com.unifidokey.app.handheld.presentation

import androidx.lifecycle.ViewModel
import com.webauthn4j.ctap.authenticator.data.event.Event
import com.webauthn4j.ctap.authenticator.data.event.EventType
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter

class HistoryItemViewModel(private val event: Event) : ViewModel() {

    val type: String
        get() {
            return when (event.type) {
                EventType.MakeCredential -> "Registration"
                EventType.GetAssertion -> "Authentication"
                EventType.Reset -> "Reset"
            }
        }

    val time: String
        get() = LocalDateTime.ofInstant(event.time, ZoneId.systemDefault())
            .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))

    val message: String
        get() = event.toString()
}