package com.unifidokey.app.handheld.presentation

import java.io.Serializable

data class CredentialSelectorDialogActivityRequest(val credentials: List<CredentialViewModel>) :
    Serializable
