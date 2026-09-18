mod pipeline;
mod sha256;

use std::process::ExitCode;

fn main() -> ExitCode {
    // Runtime hardening entry point: anti-tamper gates (anti-debug, anti-injection,
    // self-ptrace, non-dumpable) then the decode-key init then mseal, in that
    // order. A no-op unless the `anti-tamper` feature is on and the target is
    // Linux. Must run before any encrypted constant is decoded (i.e. before the
    // pipeline).
    crypt::harden();

    // Layer 3.4: keep the decoy constants alive (black_box is a DCE barrier) while
    // discarding their value, so they sit in the binary next to the real encrypted
    // constants without ever touching the output.
    core::hint::black_box(pipeline::decoys());

    let code = {
        #[cfg(feature = "introspection")]
        {
            run_dev()
        }
        #[cfg(not(feature = "introspection"))]
        {
            run_ship()
        }
    };

    // Signal a clean shutdown so the self-ptrace watchdog does not fire as the
    // sentinel follows us out.
    crypt::harden_shutdown();
    code
}

/// Development CLI (feature `introspection`): optional input path (defaults to the
/// committed fixture), verbose diagnostics on stderr, oracle hash on stdout.
#[cfg(feature = "introspection")]
fn run_dev() -> ExitCode {
    let path = std::env::args_os()
        .nth(1)
        .unwrap_or_else(|| std::ffi::OsString::from("testdata/fixed_input.bin"));
    let input = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("cannot read {}: {e}", path.to_string_lossy());
            return ExitCode::FAILURE;
        }
    };
    let out = pipeline::run(&input);
    let digest = sha256::sha256(&out);
    eprintln!(
        "input: {} bytes from {}",
        input.len(),
        path.to_string_lossy()
    );
    eprintln!("output: {} bytes", out.len());
    // stdout carries ONLY the oracle fingerprint -- identical across dev/release/ship.
    println!("{}", sha256::to_hex(&digest));
    ExitCode::SUCCESS
}

/// Shipped CLI (no `introspection`): exactly one positional arg (input path).
/// Missing/extra argument or any read error -> silent exit. Prints only the
/// oracle fingerprint on success (Layer 1.2/1.3). Exit codes stay honest.
#[cfg(not(feature = "introspection"))]
fn run_ship() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let path = match (args.next(), args.next()) {
        (Some(p), None) => p,
        _ => return ExitCode::FAILURE,
    };
    let input = match std::fs::read(&path) {
        Ok(d) => d,
        Err(_) => return ExitCode::FAILURE,
    };
    let out = pipeline::run(&input);
    let digest = sha256::sha256(&out);
    println!("{}", sha256::to_hex(&digest));
    ExitCode::SUCCESS
}
