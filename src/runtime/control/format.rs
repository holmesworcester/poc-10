use topo::db::open_connection;
use topo::service;

// ---------------------------------------------------------------------------
// Display helpers — delegated to display module
// ---------------------------------------------------------------------------

pub(crate) fn short_id(b64: &str) -> &str {
    topo::display::short_id(b64)
}

/// Show created events from a server response, respecting the display mode setting.
pub(crate) fn maybe_show_created_events(db: &str, data: &serde_json::Value) {
    use topo::db::event_display::{self, EventDisplayMode};

    let Some(events_json) = data.get("created_events") else {
        return;
    };
    let Ok(events): Result<Vec<service::EventListItem>, _> =
        serde_json::from_value(events_json.clone())
    else {
        return;
    };
    if events.is_empty() {
        return;
    }

    println!();

    // Load display mode from infra DB (direct read, no RPC).
    let mode = match open_connection(db) {
        Ok(conn) => {
            let _ = event_display::ensure_schema(&conn);
            event_display::load_mode(&conn).unwrap_or(EventDisplayMode::Tree)
        }
        Err(_) => EventDisplayMode::Tree,
    };

    match mode {
        EventDisplayMode::Tree => topo::display::print_event_tree(&events),
        EventDisplayMode::List => topo::display::print_event_list(&events),
        EventDisplayMode::Off => {}
    }
}

pub(crate) fn system_hostname() -> String {
    let mut buf = [0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret == 0 {
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..len]).into_owned()
    } else {
        "device".to_string()
    }
}

pub(crate) fn format_timestamp(ms: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let age_ms = now - ms;

    if age_ms < 0 {
        return format_absolute(ms);
    }

    let secs = age_ms / 1000;
    if secs < 60 {
        return format!("{}s ago", secs);
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{}m ago", mins);
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{}h ago", hours);
    }
    let days = hours / 24;
    if days < 7 {
        return format!("{}d ago", days);
    }

    format_absolute(ms)
}

pub(crate) fn format_absolute(ms: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let dt = UNIX_EPOCH + Duration::from_millis(ms as u64);
    let secs = dt.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;

    let (_year, month, day) = days_to_ymd(days_since_epoch as i64);
    let month_name = match month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "???",
    };
    format!("{} {} {:02}:{:02}", month_name, day, hours, minutes)
}

pub(crate) fn format_compact_datetime(ms: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let dt = UNIX_EPOCH + Duration::from_millis(ms as u64);
    let total_secs = dt.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days_since_epoch = total_secs / 86_400;
    let time_of_day = total_secs % 86_400;
    let hours = time_of_day / 3_600;
    let minutes = (time_of_day % 3_600) / 60;
    let seconds = time_of_day % 60;
    let millis = (ms.rem_euclid(1000)) as u32;

    let (year, month, day) = days_to_ymd(days_since_epoch as i64);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        year, month, day, hours, minutes, seconds, millis
    )
}

fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

// ---------------------------------------------------------------------------
// Messages display (from JSON data)
// ---------------------------------------------------------------------------

pub(crate) fn show_messages_from_json(_db_path: &str, data: &serde_json::Value) {
    let messages = match data["messages"].as_array() {
        Some(msgs) => msgs,
        None => {
            println!("  (no messages)");
            return;
        }
    };

    if messages.is_empty() {
        println!("  (no messages)");
        return;
    }

    let total = data["total"].as_i64().unwrap_or(0) as usize;
    println!("MESSAGES ({} total):\n", total);

    let skipped = if total > messages.len() {
        total - messages.len()
    } else {
        0
    };
    if skipped > 0 {
        println!("  ({} older messages not shown)\n", skipped);
    }

    let mut last_author = String::new();
    for (i, msg) in messages.iter().enumerate() {
        let created_at = msg["created_at"].as_i64().unwrap_or(0);
        let ts = format_timestamp(created_at);
        let author_id = msg["author_id"].as_str().unwrap_or("");
        let author_name = msg["author_name"].as_str().unwrap_or("");
        let display_name = if author_name.is_empty() {
            short_id(author_id).to_string()
        } else {
            author_name.to_string()
        };
        let content = msg["content"].as_str().unwrap_or("");

        if author_id != last_author {
            if i > 0 {
                println!();
            }
            println!("  {} [{}]", display_name, ts);
            last_author = author_id.to_string();
        }
        println!("    {}. {}", skipped + i + 1, content);

        // Reactions: Slack-style grouped counts on one line
        if let Some(reactions) = msg["reactions"].as_array() {
            if !reactions.is_empty() {
                let mut counts: std::collections::BTreeMap<String, usize> =
                    std::collections::BTreeMap::new();
                for r in reactions {
                    let emoji = r["emoji"].as_str().unwrap_or("?").to_string();
                    *counts.entry(emoji).or_default() += 1;
                }
                let parts: Vec<String> = counts
                    .iter()
                    .map(|(name, count)| {
                        let glyph = emoji_shortcode_to_unicode(name);
                        if *count > 1 {
                            format!("{} ({})", glyph, count)
                        } else {
                            glyph.to_string()
                        }
                    })
                    .collect();
                println!("        {}", parts.join("  "));
            }
        }

        // Files: checkmark = complete, hourglass = syncing
        if let Some(files) = msg["files"].as_array() {
            for att in files {
                let filename = att["filename"].as_str().unwrap_or("file");
                let blob_bytes = att["blob_bytes"].as_i64().unwrap_or(0);
                let total = att["total_slices"].as_i64().unwrap_or(0);
                let received = att["slices_received"].as_i64().unwrap_or(0);
                let complete = total > 0 && received >= total;
                let download_rate_mib_s = att["download_rate_mib_s"].as_f64();
                println!(
                    "        {}",
                    format_file_display(
                        filename,
                        blob_bytes,
                        complete,
                        total,
                        received,
                        download_rate_mib_s,
                    )
                );
            }
        }
    }
    println!();
}

pub(crate) fn emoji_shortcode_to_unicode(name: &str) -> &str {
    match name {
        "thumbsup" | "+1" => "\u{1f44d}",
        "thumbsdown" | "-1" => "\u{1f44e}",
        "heart" | "red_heart" => "\u{2764}\u{fe0f}",
        "laugh" | "joy" => "\u{1f602}",
        "cry" | "sob" => "\u{1f62d}",
        "fire" => "\u{1f525}",
        "rocket" => "\u{1f680}",
        "eyes" => "\u{1f440}",
        "tada" | "party" => "\u{1f389}",
        "100" => "\u{1f4af}",
        "wave" => "\u{1f44b}",
        "clap" => "\u{1f44f}",
        "thinking" | "thinking_face" => "\u{1f914}",
        "pray" | "folded_hands" => "\u{1f64f}",
        "ok_hand" => "\u{1f44c}",
        "raised_hands" => "\u{1f64c}",
        "star" => "\u{2b50}",
        "sparkles" => "\u{2728}",
        "check" | "white_check_mark" => "\u{2705}",
        "x" | "cross_mark" => "\u{274c}",
        "warning" => "\u{26a0}\u{fe0f}",
        "question" => "\u{2753}",
        "exclamation" => "\u{2757}",
        "smile" | "smiley" => "\u{1f604}",
        "wink" => "\u{1f609}",
        "sunglasses" | "cool" => "\u{1f60e}",
        "sad" | "disappointed" => "\u{1f61e}",
        "angry" => "\u{1f620}",
        "scream" => "\u{1f631}",
        "skull" => "\u{1f480}",
        "poop" => "\u{1f4a9}",
        "muscle" => "\u{1f4aa}",
        "brain" => "\u{1f9e0}",
        "bulb" | "light_bulb" => "\u{1f4a1}",
        "memo" => "\u{1f4dd}",
        "pin" | "pushpin" => "\u{1f4cc}",
        "link" => "\u{1f517}",
        "bug" => "\u{1f41b}",
        "wrench" => "\u{1f527}",
        "hammer" => "\u{1f528}",
        "gear" => "\u{2699}\u{fe0f}",
        "lock" => "\u{1f512}",
        "key" => "\u{1f511}",
        "bell" => "\u{1f514}",
        "megaphone" | "loudspeaker" => "\u{1f4e3}",
        _ => name, // pass through unknown shortcodes as-is
    }
}

pub(crate) fn format_byte_size(bytes: i64) -> String {
    const KIB: i64 = 1024;
    const MIB: i64 = 1024 * 1024;
    const GIB: i64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

pub(crate) fn format_download_rate_mib_s(download_rate_mib_s: Option<f64>) -> Option<String> {
    let rate = download_rate_mib_s?;
    if !rate.is_finite() || rate <= 0.0 {
        return None;
    }
    Some(format!("{rate:.2} MiB/s"))
}

pub(crate) fn format_file_display(
    filename: &str,
    blob_bytes: i64,
    complete: bool,
    total_slices: i64,
    slices_received: i64,
    download_rate_mib_s: Option<f64>,
) -> String {
    let status = if complete { "\u{2714}" } else { "\u{23f3}" };
    let size = format_byte_size(blob_bytes);

    if !complete {
        if total_slices > 0 {
            let pct = (slices_received as f64 / total_slices as f64 * 100.0) as u32;
            return format!("{status}  {filename} ({size}, {pct}%)");
        }
        return format!("{status}  {filename} ({size})");
    }

    match format_download_rate_mib_s(download_rate_mib_s) {
        Some(rate) => format!("{status}  {filename} ({size}, {rate})"),
        None => format!("{status}  {filename} ({size})"),
    }
}

pub(crate) fn show_view(data: &serde_json::Value) {
    let workspace_name = data["workspace_name"].as_str().unwrap_or("(unnamed)");
    let own_user_eid = data["own_user_event_id"].as_str().unwrap_or("");

    println!("TENANTS:");
    if let Some(tenants) = data["tenants"]
        .as_array()
        .or_else(|| data["accounts"].as_array())
    {
        if tenants.is_empty() {
            println!("  (none)");
        } else {
            for (idx, tenant) in tenants.iter().enumerate() {
                let marker = if tenant["active"].as_bool().unwrap_or(false) {
                    "*"
                } else {
                    " "
                };
                let tenant_eid = tenant["event_id"].as_str().unwrap_or("");
                let username = tenant["username"].as_str().unwrap_or("");
                let workspace_name = tenant["workspace_name"].as_str().unwrap_or("");
                let workspace_id = tenant["workspace_id"].as_str().unwrap_or("");
                let user_display = if username.is_empty() {
                    short_id(tenant["peer_id"].as_str().unwrap_or("")).to_string()
                } else {
                    username.to_string()
                };
                let workspace_display = if workspace_name.is_empty() {
                    short_id(workspace_id).to_string()
                } else {
                    workspace_name.to_string()
                };
                let joining_tag = if tenant["ready"].as_bool().unwrap_or(false) {
                    ""
                } else {
                    " [still joining]"
                };
                println!(
                    "  {}. {} {} {}@{}{}",
                    idx + 1,
                    marker,
                    short_id(tenant_eid),
                    user_display,
                    workspace_display,
                    joining_tag
                );
            }
        }
    }

    println!();
    println!("WORKSPACE:");
    println!("  {}", workspace_name);
    println!();
    println!("  USERS:");

    if let Some(users) = data["users"].as_array() {
        if users.is_empty() {
            println!("    (none)");
        } else {
            for user in users {
                let username = user["username"].as_str().unwrap_or("");
                let device_name = user["device_name"].as_str().unwrap_or("");
                let user_eid = user["event_id"].as_str().unwrap_or("");
                let user_display = if username.is_empty() {
                    short_id(user_eid).to_string()
                } else {
                    username.to_string()
                };
                let label = if device_name.is_empty() {
                    user_display
                } else {
                    format!("{}/{}", user_display, device_name)
                };
                if user_eid == own_user_eid {
                    println!("    {} (you)", label);
                } else {
                    println!("    {}", label);
                }
            }
        }
    }

    println!();
    println!("  {}", "\u{2500}".repeat(40));
    println!();

    // Messages with inline reactions
    if let Some(messages) = data["messages"].as_array() {
        if messages.is_empty() {
            println!("    (no messages)");
        } else {
            let mut last_author = String::new();
            for (i, msg) in messages.iter().enumerate() {
                let created_at = msg["created_at"].as_i64().unwrap_or(0);
                let ts = format_timestamp(created_at);
                let author_id = msg["author_id"].as_str().unwrap_or("");
                let author_name = msg["author_name"].as_str().unwrap_or("");
                let display_name = if author_name.is_empty() {
                    short_id(author_id).to_string()
                } else {
                    author_name.to_string()
                };
                let content = msg["content"].as_str().unwrap_or("");

                if author_id != last_author {
                    if i > 0 {
                        println!();
                    }
                    println!("    {} [{}]", display_name, ts);
                    last_author = author_id.to_string();
                }
                println!("      {}. {}", i + 1, content);

                // Inline reactions
                if let Some(reactions) = msg["reactions"].as_array() {
                    if !reactions.is_empty() {
                        let mut counts: std::collections::BTreeMap<String, usize> =
                            std::collections::BTreeMap::new();
                        for r in reactions {
                            let emoji = r["emoji"].as_str().unwrap_or("?").to_string();
                            *counts.entry(emoji).or_default() += 1;
                        }
                        let parts: Vec<String> = counts
                            .iter()
                            .map(|(name, count)| {
                                let glyph = emoji_shortcode_to_unicode(name);
                                if *count > 1 {
                                    format!("{} ({})", glyph, count)
                                } else {
                                    glyph.to_string()
                                }
                            })
                            .collect();
                        println!("         {}", parts.join("  "));
                    }
                }

                // Inline file attachments
                if let Some(files) = msg["files"].as_array() {
                    for att in files {
                        let filename = att["filename"].as_str().unwrap_or("file");
                        let blob_bytes = att["blob_bytes"].as_i64().unwrap_or(0);
                        let total = att["total_slices"].as_i64().unwrap_or(0);
                        let received = att["slices_received"].as_i64().unwrap_or(0);
                        let size = format_byte_size(blob_bytes);
                        let status = if total > 0 && received >= total {
                            "\u{2714}" // checkmark
                        } else {
                            "\u{23f3}" // hourglass
                        };
                        if total > 0 && received < total {
                            let pct = (received as f64 / total as f64 * 100.0) as u32;
                            println!("         {}  {} ({}, {}%)", status, filename, size, pct);
                        } else {
                            println!("         {}  {} ({})", status, filename, size);
                        }
                    }
                }
            }
        }
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emoji_shortcode_known() {
        assert_eq!(emoji_shortcode_to_unicode("thumbsup"), "\u{1f44d}");
        assert_eq!(emoji_shortcode_to_unicode("+1"), "\u{1f44d}");
        assert_eq!(emoji_shortcode_to_unicode("heart"), "\u{2764}\u{fe0f}");
        assert_eq!(emoji_shortcode_to_unicode("fire"), "\u{1f525}");
        assert_eq!(emoji_shortcode_to_unicode("rocket"), "\u{1f680}");
        assert_eq!(emoji_shortcode_to_unicode("tada"), "\u{1f389}");
    }

    #[test]
    fn test_emoji_shortcode_unknown_passthrough() {
        assert_eq!(emoji_shortcode_to_unicode("zzz_unknown"), "zzz_unknown");
    }

    #[test]
    fn test_format_byte_size() {
        assert_eq!(format_byte_size(0), "0 B");
        assert_eq!(format_byte_size(512), "512 B");
        assert_eq!(format_byte_size(1024), "1.0 KiB");
        assert_eq!(format_byte_size(1536), "1.5 KiB");
        assert_eq!(format_byte_size(1048576), "1.0 MiB");
        assert_eq!(format_byte_size(1258291), "1.2 MiB");
        assert_eq!(format_byte_size(1073741824), "1.0 GiB");
    }

    #[test]
    fn test_format_file_display_complete_with_rate() {
        assert_eq!(
            format_file_display("payload.bin", 12 * 1024 * 1024, true, 48, 48, Some(3.42)),
            "\u{2714}  payload.bin (12.0 MiB, 3.42 MiB/s)"
        );
    }

    #[test]
    fn test_format_file_display_complete_without_rate() {
        assert_eq!(
            format_file_display("payload.bin", 12 * 1024 * 1024, true, 48, 48, None),
            "\u{2714}  payload.bin (12.0 MiB)"
        );
    }

    #[test]
    fn test_format_file_display_incomplete_uses_percentage_only() {
        assert_eq!(
            format_file_display("payload.bin", 12 * 1024 * 1024, false, 48, 36, Some(3.42)),
            "\u{23f3}  payload.bin (12.0 MiB, 75%)"
        );
    }
}
