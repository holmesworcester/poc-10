//! Protocol-version ceiling and release-profile decisions.
//!
//! This module owns the protocol-neutral part of versioning: computing the
//! read/admit ceiling from signed release metadata and trusted time, deciding
//! which fact version a release profile is allowed to author, and classifying
//! received bytes as active or pending before protocol code interprets them.
//! It deliberately does not know fact-family semantics, byte layouts,
//! signatures, sync policy, or row meaning.
//!
//! The important split is permission versus activation. The ceiling is a
//! permission bound over what this node may safely admit, render, and share.
//! A release profile separately declares which fact versions this binary can
//! write. A binary may therefore continue writing an older shape after the
//! ceiling permits a newer one; switching writers is a release-profile change,
//! not a side effect of time passing inside a running client.

/// Fleet-wide protocol version.
pub type ProtocolVersion = u32;

/// Store-local trusted time in milliseconds.
///
/// Versioning uses trusted time as a monotonic lower bound on real time. A stale
/// observation blocks shared production because a node should not infer that an
/// old blocker has expired from untrusted wall-clock time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedTime {
    pub now_ms: u64,
    pub fresh: bool,
}

impl TrustedTime {
    pub const fn fresh(now_ms: u64) -> Self {
        Self {
            now_ms,
            fresh: true,
        }
    }

    pub const fn stale(now_ms: u64) -> Self {
        Self {
            now_ms,
            fresh: false,
        }
    }
}

/// Contiguous protocol support advertised by one release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolRange {
    pub start: ProtocolVersion,
    pub end: ProtocolVersion,
}

impl ProtocolRange {
    pub const fn new(start: ProtocolVersion, end: ProtocolVersion) -> Self {
        Self { start, end }
    }

    pub const fn contains(self, version: ProtocolVersion) -> bool {
        self.start <= version && version <= self.end
    }
}

/// Signed release metadata after signature verification by the caller.
///
/// The signature and provider identity are intentionally not represented here:
/// protocol code verifies and persists those observations, then hands core this
/// already-authenticated summary for ceiling calculation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseManifestEntry {
    pub release_id: String,
    pub platform: String,
    pub supported_protocol: ProtocolRange,
    pub expires_at_ms: u64,
    pub security_deprecated: bool,
}

impl ReleaseManifestEntry {
    fn constrains_ceiling_at(&self, trusted_time_ms: u64, skew_margin_ms: u64) -> bool {
        !self.security_deprecated
            && trusted_time_ms <= self.expires_at_ms.saturating_add(skew_margin_ms)
    }
}

/// Reason a node cannot safely compute a production ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeilingBlockReason {
    TrustedTimeStale,
    NoStillUsableRelease,
}

/// Result of evaluating the release manifest at one trusted time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CeilingStatus {
    pub ceiling: Option<ProtocolVersion>,
    pub constraining_releases: Vec<String>,
    pub blocked: Option<CeilingBlockReason>,
}

impl CeilingStatus {
    pub fn active_ceiling(&self) -> Result<ProtocolVersion, CeilingBlockReason> {
        match (self.ceiling, self.blocked) {
            (Some(ceiling), None) => Ok(ceiling),
            (_, Some(reason)) => Err(reason),
            (None, None) => Err(CeilingBlockReason::NoStillUsableRelease),
        }
    }
}

/// Compute the protocol ceiling from release metadata and trusted time.
///
/// A release constrains the ceiling until its expiry plus the skew margin has
/// passed. Security-deprecated releases stop constraining immediately because a
/// signed canary says they are no longer still-usable.
pub fn compute_ceiling(
    entries: &[ReleaseManifestEntry],
    trusted_time: TrustedTime,
    skew_margin_ms: u64,
) -> CeilingStatus {
    if !trusted_time.fresh {
        return CeilingStatus {
            ceiling: None,
            constraining_releases: Vec::new(),
            blocked: Some(CeilingBlockReason::TrustedTimeStale),
        };
    }

    let constraining = entries
        .iter()
        .filter(|entry| entry.constrains_ceiling_at(trusted_time.now_ms, skew_margin_ms))
        .collect::<Vec<_>>();

    let ceiling = constraining
        .iter()
        .map(|entry| entry.supported_protocol.end)
        .min();
    let constraining_releases = constraining
        .iter()
        .map(|entry| entry.release_id.clone())
        .collect::<Vec<_>>();
    let blocked = if ceiling.is_some() {
        None
    } else {
        Some(CeilingBlockReason::NoStillUsableRelease)
    };

    CeilingStatus {
        ceiling,
        constraining_releases,
        blocked,
    }
}

/// One fact-family author compiled into a release profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyWriter {
    pub family: &'static str,
    pub version: ProtocolVersion,
}

/// Release-local read/write profile.
///
/// `read_head` is what this binary can decode, authenticate, adapt, and
/// project. `writers` is intentionally separate and fixed by the release: it
/// records what this binary chooses to emit when commands author new facts.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseProfile {
    pub release_id: &'static str,
    pub read_head: ProtocolVersion,
    pub writers: &'static [FamilyWriter],
}

impl ReleaseProfile {
    pub fn supports_read(self, version: ProtocolVersion) -> bool {
        version <= self.read_head
    }

    pub fn write_version(
        self,
        family: &'static str,
        ceiling: ProtocolVersion,
    ) -> Result<ProtocolVersion, WriteVersionError> {
        let writer = self
            .writers
            .iter()
            .find(|writer| writer.family == family)
            .copied()
            .ok_or(WriteVersionError::NoAuthor { family })?;
        if writer.version > ceiling {
            return Err(WriteVersionError::AboveCeiling {
                family,
                writer_version: writer.version,
                ceiling,
            });
        }
        Ok(writer.version)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteVersionError {
    NoAuthor {
        family: &'static str,
    },
    AboveCeiling {
        family: &'static str,
        writer_version: ProtocolVersion,
        ceiling: ProtocolVersion,
    },
}

/// Admission state for bytes received from an authenticated sync/transport path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressClassification {
    Active,
    Pending(PendingReason),
    Dropped(DropReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingReason {
    UnknownTag,
    AboveCeiling {
        intro_version: ProtocolVersion,
        ceiling: ProtocolVersion,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    UnauthenticatedSource,
}

/// Decide whether received bytes may become an active fact at this ceiling.
///
/// Unknown tags and above-ceiling tags stay pending only after the caller has
/// established the sync/transport source is authenticated. Unauthenticated
/// bytes do not get retained as pending evidence.
pub fn classify_received_fact(
    route_intro_version: Option<ProtocolVersion>,
    ceiling: ProtocolVersion,
    authenticated_source: bool,
) -> IngressClassification {
    if !authenticated_source {
        return IngressClassification::Dropped(DropReason::UnauthenticatedSource);
    }
    let Some(intro_version) = route_intro_version else {
        return IngressClassification::Pending(PendingReason::UnknownTag);
    };
    if intro_version > ceiling {
        IngressClassification::Pending(PendingReason::AboveCeiling {
            intro_version,
            ceiling,
        })
    } else {
        IngressClassification::Active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAMILY: &str = "fixture";
    const V1_WRITER: &[FamilyWriter] = &[FamilyWriter {
        family: FAMILY,
        version: 1,
    }];
    const V2_WRITER: &[FamilyWriter] = &[FamilyWriter {
        family: FAMILY,
        version: 2,
    }];

    #[test]
    fn ceiling_waits_for_expiry_plus_skew_margin() {
        let entries = [
            manifest_entry("r1", ProtocolRange::new(1, 1), 100, false),
            manifest_entry("r2", ProtocolRange::new(1, 2), 1_000, false),
        ];

        let before = compute_ceiling(&entries, TrustedTime::fresh(120), 20);
        assert_eq!(before.active_ceiling(), Ok(1));
        assert_eq!(before.constraining_releases, vec!["r1", "r2"]);

        let after = compute_ceiling(&entries, TrustedTime::fresh(121), 20);
        assert_eq!(after.active_ceiling(), Ok(2));
        assert_eq!(after.constraining_releases, vec!["r2"]);
    }

    #[test]
    fn security_deprecation_removes_a_blocker_immediately() {
        let entries = [
            manifest_entry("r1", ProtocolRange::new(1, 1), 10_000, true),
            manifest_entry("r2", ProtocolRange::new(1, 2), 10_000, false),
        ];

        let status = compute_ceiling(&entries, TrustedTime::fresh(10), 20);
        assert_eq!(status.active_ceiling(), Ok(2));
        assert_eq!(status.constraining_releases, vec!["r2"]);
    }

    #[test]
    fn stale_time_blocks_ceiling_instead_of_guessing() {
        let entries = [manifest_entry("r1", ProtocolRange::new(1, 1), 100, false)];

        let status = compute_ceiling(&entries, TrustedTime::stale(1_000), 20);
        assert_eq!(
            status.active_ceiling(),
            Err(CeilingBlockReason::TrustedTimeStale)
        );
        assert!(status.constraining_releases.is_empty());
    }

    #[test]
    fn release_profile_keeps_write_activation_fixed() {
        let read_ahead = ReleaseProfile {
            release_id: "r2-read-ahead",
            read_head: 2,
            writers: V1_WRITER,
        };
        let writes_v2 = ReleaseProfile {
            release_id: "r3-write-v2",
            read_head: 2,
            writers: V2_WRITER,
        };

        assert!(read_ahead.supports_read(2));
        assert_eq!(read_ahead.write_version(FAMILY, 2), Ok(1));
        assert_eq!(writes_v2.write_version(FAMILY, 2), Ok(2));
        assert_eq!(
            writes_v2.write_version(FAMILY, 1),
            Err(WriteVersionError::AboveCeiling {
                family: FAMILY,
                writer_version: 2,
                ceiling: 1,
            })
        );
    }

    #[test]
    fn received_bytes_are_pending_until_their_tag_is_ceiling_active() {
        assert_eq!(
            classify_received_fact(Some(2), 1, true),
            IngressClassification::Pending(PendingReason::AboveCeiling {
                intro_version: 2,
                ceiling: 1,
            })
        );
        assert_eq!(
            classify_received_fact(Some(2), 2, true),
            IngressClassification::Active
        );
        assert_eq!(
            classify_received_fact(None, 2, true),
            IngressClassification::Pending(PendingReason::UnknownTag)
        );
        assert_eq!(
            classify_received_fact(Some(1), 2, false),
            IngressClassification::Dropped(DropReason::UnauthenticatedSource)
        );
    }

    fn manifest_entry(
        release_id: &'static str,
        supported_protocol: ProtocolRange,
        expires_at_ms: u64,
        security_deprecated: bool,
    ) -> ReleaseManifestEntry {
        ReleaseManifestEntry {
            release_id: release_id.to_string(),
            platform: "desktop".to_string(),
            supported_protocol,
            expires_at_ms,
            security_deprecated,
        }
    }
}
