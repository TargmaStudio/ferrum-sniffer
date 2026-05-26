use std::time;
use std::time::SystemTime;
use anyhow::Result;
use sqlx::SqlitePool;
use serde::Deserialize;

#[derive(Clone)]
pub struct PacketRecord {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub flags: Option<String>,
    pub length: u16,
}

#[derive(Deserialize)]
pub struct IpApiResponse {
    #[serde(rename = "org")]
    org: Option<String>,

    country: Option<String>,

    #[serde(rename = "query")]
    ip: String,
}

#[derive(Clone)]
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

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ip_intelligence (
                    ip           TEXT PRIMARY KEY,
                    org_name     TEXT,
                    country      TEXT,
                    network      TEXT,
                    asn          TEXT,
                    description  TEXT,
                    looked_up_at INTEGER NOT NULL,
                    first_seen   INTEGER NOT NULL,
                    last_seen    INTEGER NOT NULL,
                    hit_count    INTEGER NOT NULL DEFAULT 0
                )"
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

    pub async fn lookup_ip(&self, ip: &str) -> Result<()> {
        if is_private_ip(ip) {
            return Ok(());
        }

        let now = SystemTime::now()
            .duration_since(time::UNIX_EPOCH)?
            .as_secs() as i64;

        // Check cache first
        let cached = sqlx::query("
            SELECT looked_up_at FROM ip_intelligence
            WHERE ip = ? AND looked_up_at > ?"
        )
        .bind(ip)
        .bind(now - (7 *86400))
        .fetch_optional(&self.pool)
        .await?;

        if cached.is_some() {
            // Cache hit - just update the hit count and last_seen
            sqlx::query("
                UPDATE ip_intelligence
                SET hit_count = hit_count + 1,
                    last_seen = ?
                WHERE ip = ?
            ")
            .bind(now)
            .bind(ip)
            .execute(&self.pool)
            .await?;

            return Ok(())
        }

        // cache miss — hit the API
        let url = format!("http://ip-api.com/json/{}", ip);
        let response = reqwest::get(&url)
            .await?
            .json::<IpApiResponse>()
            .await?;

        // upsert — insert or update if exists
        sqlx::query(
            "INSERT INTO ip_intelligence
         (ip, org_name, country, looked_up_at, first_seen, last_seen, hit_count)
         VALUES (?, ?, ?, ?, ?, ?, 1)
         ON CONFLICT(ip) DO UPDATE SET
             org_name     = excluded.org_name,
             country      = excluded.country,
             looked_up_at = excluded.looked_up_at,
             last_seen    = excluded.last_seen,
             hit_count    = hit_count + 1"
        )
            .bind(&response.ip)
            .bind(&response.org)
            .bind(&response.country)
            .bind(now)
            .bind(now)
            .bind(now)
            .execute(&self.pool)
            .await?;

        Ok(())
    }
}

fn is_private_ip(ip: &str) -> bool {
    ip.starts_with("192.168.")
    || ip.starts_with("10.")
    || ip.starts_with("127.")
    || ip.starts_with("169.254.")
    || ip.starts_with("::1")
    || {
        // 172.16.0.0 - 172.31.255.255
        if let Some(second) = ip.strip_prefix("172.") {
            if let Some(num) = second.split(".").next() {
                if let Ok(n) = num.parse::<u8>() {
                    return n >= 16 && n <= 31;
                }
            }
        }

        false
    }
}
