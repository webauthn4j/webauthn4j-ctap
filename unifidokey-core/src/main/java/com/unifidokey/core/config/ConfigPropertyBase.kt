package com.unifidokey.core.config

import androidx.annotation.UiThread
import androidx.annotation.WorkerThread
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData

abstract class ConfigPropertyBase<T> internal constructor(
    protected val configManager: ConfigManager,
    val key: String,
    private val seedValue: T,
    val experimentalFeature: Boolean,
    val developerFeature: Boolean,
    val resetTarget: Boolean
) {
    private val mutableLiveData: MutableLiveData<T> by lazy {
        val initialValue = when (configManager.persistenceAdaptor.contains(key)) {
            true -> load()
            false -> {
                save(seedValue)
                seedValue
            }
        }
        val mutableLiveData = MutableLiveData(initialValue)
        mutableLiveData.observeForever { value -> save(value) }
        return@lazy mutableLiveData
    }
    val liveData: LiveData<T> by lazy { mutableLiveData }

    var value: T
        get() {
            @Suppress("UNCHECKED_CAST")
            return liveData.value as T
        }
        @UiThread
        set(value) {
            if (this.mutableLiveData.value != value) {
                this.mutableLiveData.value = value
            }
        }

    val enabled: Boolean
        get(){
            val developerModeEvaluationResult = when(developerFeature){
                true -> when(configManager.developerMode.value){
                    true -> true
                    false -> false
                }
                false -> true
            }
            val experimentalModeEvaluationResult = when(experimentalFeature){
                true -> when(configManager.experimentalMode.value){
                    true -> true
                    false -> false
                }
                false -> true
            }
            return developerModeEvaluationResult && experimentalModeEvaluationResult
        }

    @WorkerThread
    fun postValue(value: T) {
        this.mutableLiveData.postValue(value)
    }

    fun reset() {
        value = seedValue
    }

    protected abstract fun save(value: T)

    @Throws(ConfigNotFoundException::class)
    protected abstract fun load(): T


}