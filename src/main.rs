
fn main() {
    crypt::init_keying();

    let scale = crypt::encf!(1.35);
    let limit = crypt::enci!(90);

    if some_error_condition() {
        eprintln!("{}", crypt::obfstr_err!("configuration is invalid"));
        std::process::exit(1);
    }

    println!("scale={scale} limit={limit}");
}

fn some_error_condition() -> bool { false }