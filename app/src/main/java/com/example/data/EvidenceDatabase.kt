package com.example.data

import android.content.Context
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "evidence_reports")
data class EvidenceReportEntity(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val title: String,
    val category: String, // "DEX_BINARY", "ELF_NATIVE", "APK_AUDIT", "WEB_TRACE"
    val magicFormat: String,
    val summaryMetrics: String,
    val detailedEvidence: String,
    val engineerNotes: String = "",
    val isPinned: Boolean = false,
    val timestamp: Long = System.currentTimeMillis()
)

@Dao
interface EvidenceDao {
    @Query("SELECT * FROM evidence_reports ORDER BY isPinned DESC, timestamp DESC")
    fun getAllReports(): Flow<List<EvidenceReportEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertReport(report: EvidenceReportEntity): Long

    @Update
    suspend fun updateReport(report: EvidenceReportEntity)

    @Query("DELETE FROM evidence_reports WHERE id = :id")
    suspend fun deleteReportById(id: Int)

    @Query("SELECT COUNT(*) FROM evidence_reports")
    suspend fun getCount(): Int
}

@Database(entities = [EvidenceReportEntity::class], version = 1, exportSchema = false)
abstract class EvidenceDatabase : RoomDatabase() {
    abstract fun evidenceDao(): EvidenceDao

    companion object {
        @Volatile
        private var INSTANCE: EvidenceDatabase? = null

        fun getInstance(context: Context): EvidenceDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    EvidenceDatabase::class.java,
                    "rea_evidence_vault.db"
                ).build()
                INSTANCE = instance
                instance
            }
        }
    }
}

class EvidenceRepository(private val dao: EvidenceDao) {
    val allReports: Flow<List<EvidenceReportEntity>> = dao.getAllReports()

    suspend fun insert(report: EvidenceReportEntity): Long = dao.insertReport(report)

    suspend fun update(report: EvidenceReportEntity) = dao.updateReport(report)

    suspend fun deleteById(id: Int) = dao.deleteReportById(id)

    suspend fun getCount(): Int = dao.getCount()
}
