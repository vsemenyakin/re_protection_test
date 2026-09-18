//! The deterministic "inference" pipeline.
//!
//! This stands in for the vision pipeline of the assignment: it takes raw input
//! bytes from outside (Layer 1.1), runs a fixed computation whose numeric IP
//! (preprocessing scale/mean, a decision threshold, a mixing modulus) is held in
//! encrypted constants (Layer 3, `crypt::encf!`/`enci!`), and returns output
//! bytes. The caller fingerprints those bytes (Layer 0.2 oracle).
//!
//! Determinism: same input + same target -> byte-identical output, in every
//! build. The encrypted constants decode to the same plaintext in dev/release
//! (key = K) and in the sealed `ship` build (self-integrity key resolves to K on
//! genuine hardware), so hardening does not move the oracle.

/// Run the pipeline over `input`, returning the output bytes.
///
/// `#[inline(never)]` so it survives LTO as a named function and receives the
/// heavy *crown* obfuscation (Layer 4). This does not reintroduce a shared
/// constant decoder (Layer 3.1's warning): the per-site `encf!`/`enci!` decode
/// still expands inline *within* this function; only the pipeline body is kept
/// out-of-line.
#[inline(never)]
pub fn run(input: &[u8]) -> Vec<u8> {
    // --- Numeric IP: encrypted constants, decoded inline per site. ---
    // Preprocessing (mean/scale normalisation), echoing a vision preprocessor.
    let scale = crypt::encf!(1.35);
    let mean = crypt::encf!(0.5);
    // Postprocessing / decision.
    let limit = crypt::enci!(90);
    let threshold = crypt::enci!(128);
    // Temporal-state mixing modulus (48-bit) and seed.
    let modulus = crypt::enci!(281_474_976_710_656); // 2^48
    let mut acc: i64 = crypt::enci!(2_166_136_261);

    let mut out = Vec::with_capacity(input.len());
    for (i, &b) in input.iter().enumerate() {
        // Preprocess: normalise to [-mean, 1-mean] then scale, quantise to millis.
        let x = ((b as f64) / 255.0 - mean) * scale;
        let q = (x * 1000.0).round() as i64;

        // Mix into the running accumulator (temporal state), keep 48 bits.
        acc = acc.wrapping_mul(limit).wrapping_add(q).rem_euclid(modulus);

        // Decision rule -> numeric class code (no text labels; Layer 1.4).
        let class = if (acc % 256) > threshold { 1u8 } else { 0u8 };

        out.push((acc as u8) ^ class.wrapping_mul(i as u8));
    }
    out
}

/// Layer 3.4: decoys. A pool of fake preprocessing / calibration / postprocessing
/// constants with plausible values, encrypted per-site by exactly the same
/// `encf!`/`enci!` machinery as the real ones. They are folded into a single word
/// and handed to `black_box` by the caller, so dead-code elimination keeps them,
/// but nothing in the pipeline ever reads the result -- so they do not move the
/// oracle. After an attacker defeats the per-site encryption they surface
/// alongside the real values, plausible and indistinguishable in form, ~3x as
/// many, hiding which thresholds are real.
#[inline(never)]
pub fn decoys() -> u64 {
    let mut a: u64 = 0;
    // Fake preprocessing (mean/std/scale), plausible ranges.
    a ^= crypt::encf!(0.485).to_bits();
    a ^= crypt::encf!(0.456).to_bits();
    a ^= crypt::encf!(0.406).to_bits();
    a ^= crypt::encf!(0.229).to_bits();
    a ^= crypt::encf!(0.224).to_bits();
    a ^= crypt::encf!(0.225).to_bits();
    a ^= crypt::encf!(1.0 / 255.0).to_bits();
    // Fake postprocessing thresholds (confidence, NMS IoU).
    a ^= crypt::encf!(0.25).to_bits();
    a ^= crypt::encf!(0.45).to_bits();
    a ^= crypt::encf!(0.50).to_bits();
    a ^= crypt::encf!(0.65).to_bits();
    a ^= crypt::encf!(0.70).to_bits();
    // Fake geometry / resize / calibration.
    a ^= crypt::enci!(640) as u64;
    a ^= crypt::enci!(416) as u64;
    a ^= crypt::enci!(320) as u64;
    a ^= crypt::enci!(1280) as u64;
    a ^= crypt::enci!(100) as u64;
    a ^= crypt::enci!(300) as u64;
    // Fake temporal / tracking parameters.
    a ^= crypt::enci!(30) as u64;
    a ^= crypt::enci!(3) as u64;
    a
}
