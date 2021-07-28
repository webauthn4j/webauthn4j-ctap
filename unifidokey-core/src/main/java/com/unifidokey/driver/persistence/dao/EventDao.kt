package com.unifidokey.driver.persistence.dao

import androidx.lifecycle.LiveData
import androidx.room.*
import com.unifidokey.driver.persistence.entity.EventEntity

@Dao
interface EventDao {

    @Transaction
    @Query("SELECT * FROM event WHERE event.id = :id")
    fun findOne(id: Long): List<EventEntity>?

    @Transaction
    @Query("SELECT * FROM event ORDER BY event.time DESC")
    fun findAll(): List<EventEntity>

    @Transaction
    @Query("SELECT * FROM event ORDER BY event.time DESC")
    fun findAllLiveData(): LiveData<List<EventEntity>>

    @Insert
    fun create(event: EventEntity): Long

    @Update
    fun update(event: EventEntity)

    @Delete
    fun delete(event: EventEntity)

    @Query("DELETE FROM event WHERE id = :id")
    fun delete(id: Long)

    @Query("DELETE FROM event")
    fun deleteAll()
}