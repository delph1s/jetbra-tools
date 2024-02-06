#cargo test -p jetbra-tools --lib cert::cert_gen::tests::test_gen_certificate -- --nocapture
#RUST_BACKTRACE=1 cargo test -p jetbra-tools --lib cert::cert_gen::tests::test_gen_certificate -- --nocapture
#RUST_BACKTRACE=1 cargo test -p jetbra-tools --lib cert::cert_gen::tests::test_rc_gen_sign -- --nocapture
cargo test -- --nocapture

#openssl x509 -in ./.cache/cert.pem -noout -text
