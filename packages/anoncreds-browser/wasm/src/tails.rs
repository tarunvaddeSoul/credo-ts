use std::cell::RefCell;
use std::collections::HashMap;

use anoncreds::cl::{
    Error as ClError, ErrorKind as ClErrorKind, RevocationTailsAccessor, RevocationTailsGenerator,
    Tail,
};
use anoncreds::tails::TailsWriter;
use sha2::{Digest, Sha256};

const TAILS_BLOB_TAG_SZ: usize = 2;
const TAIL_SIZE: usize = Tail::BYTES_REPR_SIZE;

thread_local! {
    static TAILS_STORE: RefCell<HashMap<String, Vec<u8>>> = RefCell::new(HashMap::new());
}

pub fn store_tails(hash: String, bytes: Vec<u8>) {
    TAILS_STORE.with(|store| store.borrow_mut().insert(hash, bytes));
}

pub fn get_tails(hash: &str) -> Option<Vec<u8>> {
    TAILS_STORE.with(|store| store.borrow().get(hash).cloned())
}

/// Writes generated tails into the in-memory store, keyed (and "located") by tails hash
#[derive(Debug)]
pub struct MemoryTailsWriter;

impl TailsWriter for MemoryTailsWriter {
    fn write(
        &mut self,
        generator: &mut RevocationTailsGenerator,
    ) -> Result<(String, String), anoncreds::Error> {
        let mut buf: Vec<u8> = Vec::new();
        let mut hasher = Sha256::default();
        let version = &[0u8, 2u8];
        buf.extend_from_slice(version);
        hasher.update(version);
        while let Some(tail) = generator.try_next()? {
            let tail_bytes = tail.to_bytes()?;
            buf.extend_from_slice(&tail_bytes);
            hasher.update(&tail_bytes);
        }
        let hash = bs58::encode(hasher.finalize()).into_string();
        store_tails(hash.clone(), buf);
        Ok((hash.clone(), hash))
    }
}

pub struct MemoryTailsReader(pub Vec<u8>);

impl RevocationTailsAccessor for MemoryTailsReader {
    fn access_tail(
        &self,
        tail_id: u32,
        accessor: &mut dyn FnMut(&Tail),
    ) -> Result<(), ClError> {
        let start = TAIL_SIZE * tail_id as usize + TAILS_BLOB_TAG_SZ;
        let bytes = self.0.get(start..start + TAIL_SIZE).ok_or_else(|| {
            ClError::new(ClErrorKind::InvalidState, "Could not read from tails data")
        })?;
        let tail = Tail::from_bytes(bytes)?;
        accessor(&tail);
        Ok(())
    }
}
