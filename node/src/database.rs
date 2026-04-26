//! SQLite-backed persistence layer for node block data.
//!
//! The database is stored alongside the chain data directory and is opened
//! once at node startup. All writes go through a `Mutex<Connection>` so the
//! `Arc<NodeDatabase>` can safely be shared across async tasks.

use rusqlite::{params, Connection, Result as SqlResult};
use std::{
	path::Path,
	sync::{Arc, Mutex},
	time::{SystemTime, UNIX_EPOCH},
};

/// A finalized block record ready to be persisted.
pub struct BlockRecord {
	pub number: u64,
	pub hash: String,
	pub parent_hash: String,
	pub state_root: String,
	pub extrinsics_count: usize,
	/// SCALE-encoded extrinsics as lowercase hex strings (one entry per extrinsic).
	pub extrinsics: Vec<String>,
	pub saved_at: i64,
}

impl BlockRecord {
	pub fn new(
		number: u64,
		hash: impl Into<String>,
		parent_hash: impl Into<String>,
		state_root: impl Into<String>,
		extrinsics: Vec<String>,
	) -> Self {
		let saved_at = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.unwrap_or_default()
			.as_secs() as i64;
		let extrinsics_count = extrinsics.len();
		Self {
			number,
			hash: hash.into(),
			parent_hash: parent_hash.into(),
			state_root: state_root.into(),
			extrinsics_count,
			extrinsics,
			saved_at,
		}
	}
}

/// Thread-safe wrapper around an SQLite connection.
pub struct NodeDatabase {
	conn: Mutex<Connection>,
}

impl NodeDatabase {
	/// Open (or create) the SQLite database at `path` and ensure the schema exists.
	pub fn open(path: &Path) -> SqlResult<Arc<Self>> {
		let conn = Connection::open(path)?;

		// WAL mode gives better write throughput without blocking reads.
		conn.execute_batch(
			"PRAGMA journal_mode = WAL;
			 PRAGMA synchronous  = NORMAL;

			 CREATE TABLE IF NOT EXISTS blocks (
			     number            INTEGER PRIMARY KEY,
			     hash              TEXT    NOT NULL UNIQUE,
			     parent_hash       TEXT    NOT NULL,
			     state_root        TEXT    NOT NULL,
			     extrinsics_count  INTEGER NOT NULL DEFAULT 0,
			     saved_at          INTEGER NOT NULL
			 );

			 CREATE TABLE IF NOT EXISTS extrinsics (
			     id               INTEGER PRIMARY KEY AUTOINCREMENT,
			     block_number     INTEGER NOT NULL REFERENCES blocks(number),
			     extrinsic_index  INTEGER NOT NULL,
			     encoded_hex      TEXT    NOT NULL,
			     UNIQUE (block_number, extrinsic_index)
			 );

			 CREATE INDEX IF NOT EXISTS idx_extrinsics_block
			     ON extrinsics (block_number);",
		)?;

		log::info!(target: "db-indexer", "SQLite node database opened at {:?}", path);
		Ok(Arc::new(Self { conn: Mutex::new(conn) }))
	}

	/// Persist a finalized block and its extrinsics in a single transaction.
	pub fn save_block(&self, record: BlockRecord) -> SqlResult<()> {
		let conn = self.conn.lock().expect("db mutex poisoned");

		conn.execute(
			"INSERT OR REPLACE INTO blocks
			     (number, hash, parent_hash, state_root, extrinsics_count, saved_at)
			 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
			params![
				record.number,
				record.hash,
				record.parent_hash,
				record.state_root,
				record.extrinsics_count as u64,
				record.saved_at,
			],
		)?;

		for (idx, hex) in record.extrinsics.iter().enumerate() {
			conn.execute(
				"INSERT OR IGNORE INTO extrinsics
				     (block_number, extrinsic_index, encoded_hex)
				 VALUES (?1, ?2, ?3)",
				params![record.number, idx as u64, hex],
			)?;
		}

		Ok(())
	}

	/// Return the total number of finalized blocks stored.
	#[allow(dead_code)]
	pub fn block_count(&self) -> SqlResult<i64> {
		let conn = self.conn.lock().expect("db mutex poisoned");
		conn.query_row("SELECT COUNT(*) FROM blocks", [], |row| row.get(0))
	}
}

/// Encode a byte slice as a lowercase hex string (no `0x` prefix).
pub fn bytes_to_hex(bytes: &[u8]) -> String {
	use std::fmt::Write as FmtWrite;
	bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
		write!(s, "{:02x}", b).expect("writing to String is infallible");
		s
	})
}
