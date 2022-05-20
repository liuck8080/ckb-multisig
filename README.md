# ckb-multisig

Build contracts:

``` sh
git submodule init
git submodule update
make -C contracts/ckb-multisig/ckb-lib-secp256k1/ all-over-docker
capsule build
```

Run tests:
See [documents](orig-tests/README.md) for orig-tests.
