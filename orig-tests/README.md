How to test:
1. following the instructions of [ckb-system-scripts](https://github.com/nervosnetwork/ckb-system-scripts) to build the spec/cells, if the `specs/cells/secp256k1_data` file does not apear, call `make clean && make all-via-docker` again;
2. make a soft link of `specs/cells/secp256k1_data` to current working directory.
3. in parent directory, call `capsule build`
3. make a soft link of `../../../target/riscv64imac-unknown-none-elf/debug/ckb-multisig` to `spec/cells/ckb-multisig`.
4. call `cargo test`