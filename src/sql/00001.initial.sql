CREATE TABLE IF NOT EXISTS packets (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip       TEXT    NOT NULL,
    destination_ip  TEXT    NOT NULL,
    source_port     INTEGER NOT NULL,
    destination_port INTEGER NOT NULL,
    protocol        TEXT    NOT NULL,
    flags           TEXT,
    packet_length   INTEGER NOT NULL,
    captured_at     INTEGER NOT NULL
);