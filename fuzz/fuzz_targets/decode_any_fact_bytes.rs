#![no_main]

use libfuzzer_sys::fuzz_target;
use topo::protocol::fuzzing::{decode_registered_fact_bytes, REGISTERED_FACT_DECODERS};

fuzz_target!(|data: &[u8]| {
    for decoder in REGISTERED_FACT_DECODERS {
        let _ = decoder.decode(data);
    }
    let _ = decode_registered_fact_bytes(data);
});
