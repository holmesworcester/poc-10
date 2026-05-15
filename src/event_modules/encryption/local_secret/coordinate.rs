//! History-node coordinate validation shared by local-secret and key-wrap layouts.

use crate::core::facts::FactId;

pub fn validate_history_node_coordinate(
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: FactId,
) -> Result<(), String> {
    if range_width == 0 || !range_width.is_power_of_two() {
        return Err(
            "history-node key wrap range_width must be a non-zero power of two".to_string(),
        );
    }
    if range_start % range_width != 0 {
        return Err("history-node key wrap range_start must be aligned to range_width".to_string());
    }
    if bit_depth > 256 {
        return Err("history-node key wrap bit_depth is out of range".to_string());
    }
    if event_id_prefix != mask_prefix_to_depth(event_id_prefix, bit_depth) {
        return Err(
            "history-node key wrap event_id_prefix must be masked to bit_depth".to_string(),
        );
    }
    if range_width > 1 && (bit_depth != 0 || event_id_prefix != [0; 32]) {
        return Err("history-node key wrap time ranges must have empty trie prefix".to_string());
    }
    Ok(())
}

pub fn mask_prefix_to_depth(mut prefix: FactId, bit_depth: u16) -> FactId {
    let bit_depth = bit_depth as usize;
    if bit_depth >= 256 {
        return prefix;
    }
    let byte_index = bit_depth / 8;
    let remaining_bits = bit_depth % 8;
    if remaining_bits == 0 {
        prefix[byte_index..].fill(0);
    } else {
        prefix[byte_index] &= 0xff << (8 - remaining_bits);
        prefix[byte_index + 1..].fill(0);
    }
    prefix
}
