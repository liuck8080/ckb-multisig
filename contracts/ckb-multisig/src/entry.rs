// Import from `core` instead of from `std` since we are in no-std mode
use core::{result::Result, convert::TryInto, hash::Hasher};

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::{vec, vec::Vec, borrow::ToOwned};

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    debug,
    high_level::{load_script, load_witness_args, load_tx_hash, load_input_since, QueryIter},
    ckb_types::{bytes::Bytes, prelude::*},
    ckb_constants::Source,
    error::SysError,
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
    const SINCE_VALUE_BITS:usize = 56;
    const SINCE_VALUE_MASK:u64 = 0x00ffffffffffffff;
    const SINCE_EPOCH_FRACTION_FLAG:u64 =  0b00100000;

    let since_flags = since >> SINCE_VALUE_BITS;
    let since_value = since & SINCE_VALUE_MASK;

    for i in 0.. {
        match load_input_since(i, Source::GroupOutput) {
            Ok(input_since) => {
                let input_since_flags = input_since >> SINCE_VALUE_BITS;
                let input_since_value = input_since & SINCE_VALUE_MASK;
                if since_flags != input_since_flags {
                  return Err(Error::IncorrectSinceFlags);
                } else if input_since_flags == SINCE_EPOCH_FRACTION_FLAG {
                  let ret = epoch_number_with_fraction_cmp(input_since_value, since_value);
                  if ret < 0 {
                    return Err(Error::IncorrectSinceValue);
                  }
                } else if input_since_value < since_value {
                  return Err(Error::IncorrectSinceValue);
                }
            },
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        };
    }
    Ok(())
}



/* a and b are since value,
 return 0 if a is equals to b,
 return -1 if a is less than b,
 return 1 if a is greater than b */
 fn epoch_number_with_fraction_cmp(a:u64, b:u64)-> i32 {
    let number_offset = 0;
    let number_bits = 24;
    let number_maximum_value = 1 << number_bits;
    let number_mask = number_maximum_value - 1;
    let index_offset = number_bits;
    let index_bits = 16;
    let index_maximum_value = 1 << index_bits;
    let index_mask = index_maximum_value - 1;
    let length_offset = number_bits + index_bits;
    let length_bits = 16;
    let length_maximum_value = 1 << length_bits;
    let length_mask = length_maximum_value - 1;

    /* extract a epoch */
    let a_epoch = (a >> number_offset) & number_mask;
    let a_index = (a >> index_offset) & index_mask;
    let a_len = (a >> length_offset) & length_mask;

    /* extract b epoch */
    let b_epoch = (b >> number_offset) & number_mask;
    let b_index = (b >> index_offset) & index_mask;
    let b_len = (b >> length_offset) & length_mask;

    if a_epoch < b_epoch {
      return -1;
    } else if a_epoch > b_epoch {
      return 1;
    } else {
      /* a and b is in the same epoch,
         compare a_index / a_len <=> b_index / b_len
       */
      let a_block = a_index * b_len;
      let b_block = b_index * a_len;
      /* compare block */
      if a_block < b_block {
        return -1;
      } else if a_block > b_block {
        return 1;
      } else {
        return 0;
      }
    }
  }
