CRYPT_K="0x$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')" \
  cargo build --release --features harden
strip target/release/re_protection_test
cargo run -p crypt --bin seal -- target/release/re_protection_test --page-size 4096