package com.unifidokey.app.handheld.presentation

import com.webauthn4j.ctap.authenticator.CredentialSelectionHandler
import com.webauthn4j.ctap.authenticator.store.Credential
import com.webauthn4j.util.Base64UrlUtil
import org.slf4j.LoggerFactory
import java.time.Duration
import java.time.Instant
import java.util.stream.Collectors

class CachingCredentialSelectionHandler(private val credentialSelectionHandler: CredentialSelectionHandler) :
    CredentialSelectionHandler {
    private val logger = LoggerFactory.getLogger(CachingCredentialSelectionHandler::class.java)
    private var previousList: List<Credential>? = null
    private var previousSelection: Credential? = null
    private var cachedAt: Instant? = null

    override suspend fun select(list: List<Credential>): Credential {
        val idList = list.stream()
            .map { item -> Base64UrlUtil.encodeToString(item.credentialId) }
            .collect(Collectors.toList())
        val previousIdList = if (previousList == null) null else previousList!!.stream()
            .map { item -> Base64UrlUtil.encodeToString(item.credentialId) }
            .collect(Collectors.toList())
        return if (idList == previousIdList && cachedAt!!.isAfter(Instant.now().minus(TTL))) {
            logger.info("Cached selected credential is used.")
            previousSelection!!
        } else {
            val selection = credentialSelectionHandler.select(list)
            previousList = list
            previousSelection = selection
            cachedAt = Instant.now()
            selection
        }
    }

    companion object {
        private val TTL = Duration.ofSeconds(10)
    }
}