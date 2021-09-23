package com.webauthn4j.ctap.authenticator

/**
 * Reporter interface to correct exception to submit it to an external exception aggregator service
 */
fun interface ExceptionReporter {

    fun report(exception: Exception)
}