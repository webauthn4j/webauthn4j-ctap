package com.unifidokey.app

interface

UnifidoKeyApplication<T : UnifidoKeyComponent> {
    val unifidoKeyComponent: T
}
