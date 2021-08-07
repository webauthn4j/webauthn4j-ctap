package com.webauthn4j.ctap.authenticator

fun interface ExceptionReporter {

    fun report(exception: Exception)
}