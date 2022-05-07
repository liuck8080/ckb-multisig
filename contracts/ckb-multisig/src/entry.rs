// Import from `core` instead of from `std` since we are in no-std mode
use core::{result::Result, convert::TryInto, hash::Hasher};

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{vec, vec::Vec, borrow::ToOwned};

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    debug,
    high_level::{load_script, load_witness_args, load_tx_hash},
    ckb_types::{bytes::Bytes, prelude::*},
    ckb_constants::Source
};

use crate::error::Error;

use blake2b_ref::Blake2bBuilder;

const BLAKE160_SIZE:usize = 20;
const U64_SIZE:usize = 8;
const FLAGS_SIZE:usize = 4;
const SIGNATURE_SIZE:usize = 65;
const BLAKE2B_BLOCK_SIZE:usize = 32;

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes= script.args().unpack();
    debug!("script args is {:?}", args);

    if args.len() != BLAKE160_SIZE &&
       args.len() != BLAKE160_SIZE + U64_SIZE {
      return Err(Error::ArgumentsLen);
    }
    let since = if args.len() == BLAKE160_SIZE + U64_SIZE {
        u64::from_le_bytes(args[BLAKE160_SIZE..BLAKE160_SIZE + 8].try_into().unwrap())
    } else {0};

    let lock_bytes = {
        let witness = load_witness_args(0, Source::GroupInput)?;
        let lock_opt = witness.lock();
        if lock_opt.is_none() {
            return Err(Error::WitnessSize);
        }
        let lock_bytes = lock_opt.to_opt().unwrap();
        if lock_bytes.len() < FLAGS_SIZE {
            return Err(Error::WitnessSize);
        }
        lock_bytes
    };

    if u8::from(lock_bytes.get(0).unwrap()) != 0 {
        return Err(Error::InvalidReserveField);
    }
    let require_first_n:u8 =lock_bytes.get(1).unwrap().into();

    let threshold = u8::from(lock_bytes.get(2).unwrap());
    if threshold == 0 {
        return Err(Error::InvalidThreshold);
    }
    let pubkeys_cnt:u8 = Into::<u8>::into(lock_bytes.get(3).unwrap());
    if pubkeys_cnt == 0 {
        return Err(Error::InvalidPubkeysCnt);
    }
    if threshold > pubkeys_cnt {
        return Err(Error::InvalidThreshold);
    }
    if require_first_n > threshold {
        return Err(Error::InvalidRequireFirstN);
    }

    let multisig_script_len = FLAGS_SIZE + BLAKE160_SIZE * usize::from(pubkeys_cnt);
    let signatures_len = SIGNATURE_SIZE * usize::from(threshold);
    let required_lock_len = multisig_script_len + signatures_len;
    if lock_bytes.len() != required_lock_len {
        return Err(Error::WitnessSize);
    }

    {
        // check multisig args hash
        let mut tmp = [0;BLAKE2B_BLOCK_SIZE];
        let mut blake2b = Blake2bBuilder::new(BLAKE2B_BLOCK_SIZE).build();
        blake2b.update(&lock_bytes.as_slice()[0..multisig_script_len]);
        blake2b.finalize(&mut tmp);

        if args.as_ref() != tmp.as_slice() {
            return Err(Error::MultsigScriptHash)
        }
    }
    check_since(since)?;

    Ok(())
}

fn check_since(since:u64)->Result<(), Error> {
    Ok(())
}
