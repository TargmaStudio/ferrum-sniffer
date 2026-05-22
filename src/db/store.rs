use anyhow::Result;
use sqlx::SqlitePool;

pub struct PacketRecord {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub flags: Option<String>,
    pub length: u16,
}

pub struct Store {
    pool: SqlitePool,
}

impl Store {
    pub async fn new(path: &str) -> Result<Self> {
        let pool = SqlitePool::connect(path).await?;

        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&pool)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS packets (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip        TEXT    NOT NULL,
                destination_ip   TEXT    NOT NULL,
                source_port      INTEGER NOT NULL,
                destination_port INTEGER NOT NULL,
                protocol         TEXT    NOT NULL,
                flags            TEXT,
                packet_length    INTEGER NOT NULL,
                captured_at      INTEGER NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        Ok(Store { pool })
    }

    pub async fn insert_packet(&self, record: &PacketRecord) -> Result<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64;

        sqlx::query(
            "INSERT INTO packets
             (source_ip, destination_ip, source_port,
              destination_port, protocol, flags,
              packet_length, captured_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&record.src_ip)
        .bind(&record.dst_ip)
        .bind(record.src_port as i64)
        .bind(record.dst_port as i64)
        .bind(&record.protocol)
        .bind(&record.flags)
        .bind(record.length as i64)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn cleanup_old_packets(&self, days: i64) -> Result<u64> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs() as i64
            - (days * 86400);

        let result = sqlx::query("DELETE FROM packets WHERE captured_at < ?")
            .bind(cutoff)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected())
    }
}
