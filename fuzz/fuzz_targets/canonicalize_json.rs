#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    // The canonicalizer must reject malformed/adversarial inputs without
    // panicking, leaking payload contents, or escaping its documented bounds.
    let _ = agentguard_canonical::canonicalize_json(input);
});
