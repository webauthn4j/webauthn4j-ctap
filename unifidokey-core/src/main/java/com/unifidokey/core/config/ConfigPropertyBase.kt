package com.unifidokey.core.config

import androidx.annotation.UiThread
import androidx.annotation.WorkerThread
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData

abstract class ConfigPropertyBase<T> internal constructor(
    protected val configManager: ConfigManager,
    private val key: String,
    private val seedValue: T
) {

    private var loaded = false
    private val mutableLiveData: MutableLiveData<T> = MutableLiveData()
    val liveData: LiveData<T> by lazy { mutableLiveData }

    var value: T
        get() {
            @Suppress("UNCHECKED_CAST")
            return liveData.value as T
        }
        @UiThread
        set(value) {
            this.mutableLiveData.value = value
        }

    @WorkerThread
    fun postValue(value: T) {
        this.mutableLiveData.postValue(value)
    }

    @UiThread
    fun initialize() {
        val initialValue = when (configManager.persistenceAdaptor.contains(key)) {
            true -> load()
            false -> {
                save(seedValue)
                seedValue
            }
        }
        mutableLiveData.value = initialValue
        mutableLiveData.observeForever { value ->
            save(value)
        }
        liveData.value //initialize lazy mutableLiveData
    }

    fun reset() {
        value = seedValue
    }

    protected abstract fun save(value: T)

    @Throws(ConfigNotFoundException::class)
    protected abstract fun load(): T


}