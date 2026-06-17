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
//! The ceiling's protocol `u32` resolves through a bundle table to concrete
//! fact-family versions. A release profile separately declares which fact
//! versions this binary can write. A binary may therefore continue writing an
//! older shape after the ceiling permits a newer one; switching writers is a
//! release-profile change, not a side effect of time passing inside a running
//! client.

use std::collections::BTreeMap;

use crate::core::project_fact::{FactProjectorInfo, FactRoute};

/// Fleet-wide protocol version.
pub type ProtocolVersion = u32;

/// Version number inside one fact family.
pub type FactFamilyVersion = u32;

/// Db-local trusted time in milliseconds.
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

/// One family-version member of a protocol bundle.
///
/// A family version maps to one durable fact tag and its kept-forever
/// decoder/authenticator plus its adapter edge toward the ceiling semantic
/// value. The routed fact tag is still the versioning knob; this value is the
/// human-scale manifest coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FamilyVersion {
    pub family: &'static str,
    pub version: FactFamilyVersion,
}

/// Complete fact-family version set named by one protocol version.
///
/// Bundles are snapshots, not deltas. If protocol 3 only changes `message`, the
/// protocol 3 bundle still lists every other family at its carried-forward
/// version. That makes rendering and write gating read from one table instead
/// of replaying history at runtime.
#[derive(Debug, Clone, Copy)]
pub struct ProtocolBundle {
    pub protocol: ProtocolVersion,
    pub families: &'static [FamilyVersion],
}

impl ProtocolBundle {
    pub fn family_version(self, family: &'static str) -> Option<FactFamilyVersion> {
        self.families
            .iter()
            .find(|member| member.family == family)
            .map(|member| member.version)
    }

    pub fn contains(self, member: FamilyVersion) -> bool {
        self.family_version(member.family) == Some(member.version)
    }
}

/// Projector route label for one fact-family version.
///
/// This label is a reviewer-facing coordinate into the projector that owns
/// local decode, validation, adaptation, and semantic projection for the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactVersionProjector {
    pub project: &'static str,
}

impl FactVersionProjector {
    pub const fn new(project: &'static str) -> Self {
        Self { project }
    }

    pub const fn from_projector_info(projector_info: FactProjectorInfo) -> Self {
        Self {
            project: projector_info.project,
        }
    }

    pub const fn projector_info(self) -> FactProjectorInfo {
        FactProjectorInfo::projector(self.project)
    }
}

/// Route metadata needed to check a fact-version manifest.
///
/// Core routes also carry a projector function pointer. Versioning validation
/// deliberately ignores that executable pointer and checks only the durable
/// manifest coordinates that release reviewers need: tag and projector label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactVersionRoute {
    pub tag: u8,
    pub projector: FactVersionProjector,
}

impl FactVersionRoute {
    pub const fn new(tag: u8, projector: FactVersionProjector) -> Self {
        Self { tag, projector }
    }

    pub const fn from_fact_route(route: FactRoute) -> Self {
        Self {
            tag: route.tag,
            projector: FactVersionProjector::from_projector_info(route.projector_info),
        }
    }
}

/// Manifest entry for one durable fact-family version.
///
/// The protocol bundle table says when a family version is active. This entry
/// ties that family version to the one durable fact tag and the projector
/// that owns how to decode, validate, adapt, and project it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FactVersionManifestEntry {
    pub tag: u8,
    pub family: &'static str,
    pub version: FactFamilyVersion,
    pub active_from_protocol: ProtocolVersion,
    pub projector: FactVersionProjector,
}

impl FactVersionManifestEntry {
    pub const fn family_version(self) -> FamilyVersion {
        FamilyVersion {
            family: self.family,
            version: self.version,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolBundleError {
    Empty,
    DuplicateProtocol {
        protocol: ProtocolVersion,
    },
    NonMonotonicProtocol {
        previous: ProtocolVersion,
        current: ProtocolVersion,
    },
    DuplicateFamily {
        protocol: ProtocolVersion,
        family: &'static str,
    },
    FamilyDropped {
        protocol: ProtocolVersion,
        family: &'static str,
    },
    FamilyVersionRegression {
        protocol: ProtocolVersion,
        family: &'static str,
        previous: FactFamilyVersion,
        current: FactFamilyVersion,
    },
    UnknownProtocol {
        protocol: ProtocolVersion,
    },
    MissingFamily {
        protocol: ProtocolVersion,
        family: &'static str,
    },
}

/// Validate the static protocol bundle table.
///
/// Protocol versions must be strictly increasing. Family versions may stay the
/// same or increase, but never regress or disappear after they appear.
pub fn validate_protocol_bundles(bundles: &[ProtocolBundle]) -> Result<(), ProtocolBundleError> {
    if bundles.is_empty() {
        return Err(ProtocolBundleError::Empty);
    }

    let mut previous_protocol = None;
    let mut previous_families = BTreeMap::<&'static str, FactFamilyVersion>::new();

    for bundle in bundles {
        if let Some(previous) = previous_protocol {
            if bundle.protocol == previous {
                return Err(ProtocolBundleError::DuplicateProtocol {
                    protocol: bundle.protocol,
                });
            }
            if bundle.protocol < previous {
                return Err(ProtocolBundleError::NonMonotonicProtocol {
                    previous,
                    current: bundle.protocol,
                });
            }
        }

        let mut current_families = BTreeMap::new();
        for member in bundle.families {
            if current_families
                .insert(member.family, member.version)
                .is_some()
            {
                return Err(ProtocolBundleError::DuplicateFamily {
                    protocol: bundle.protocol,
                    family: member.family,
                });
            }
            if let Some(previous_version) = previous_families.get(member.family) {
                if member.version < *previous_version {
                    return Err(ProtocolBundleError::FamilyVersionRegression {
                        protocol: bundle.protocol,
                        family: member.family,
                        previous: *previous_version,
                        current: member.version,
                    });
                }
            }
        }

        for family in previous_families.keys().copied() {
            if !current_families.contains_key(family) {
                return Err(ProtocolBundleError::FamilyDropped {
                    protocol: bundle.protocol,
                    family,
                });
            }
        }

        previous_protocol = Some(bundle.protocol);
        previous_families = current_families;
    }

    Ok(())
}

/// Look up the complete family-version set for one protocol version.
pub fn bundle_for_protocol(
    bundles: &[ProtocolBundle],
    protocol: ProtocolVersion,
) -> Result<ProtocolBundle, ProtocolBundleError> {
    validate_protocol_bundles(bundles)?;
    bundles
        .iter()
        .copied()
        .find(|bundle| bundle.protocol == protocol)
        .ok_or(ProtocolBundleError::UnknownProtocol { protocol })
}

/// Look up one family's version in the named protocol bundle.
pub fn family_version_for_protocol(
    bundles: &[ProtocolBundle],
    protocol: ProtocolVersion,
    family: &'static str,
) -> Result<FactFamilyVersion, ProtocolBundleError> {
    let bundle = bundle_for_protocol(bundles, protocol)?;
    bundle
        .family_version(family)
        .ok_or(ProtocolBundleError::MissingFamily { protocol, family })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactVersionManifestError {
    EmptyManifest,
    InvalidBundleTable {
        error: ProtocolBundleError,
    },
    DuplicateTag {
        tag: u8,
    },
    DuplicateFamilyVersion {
        family: &'static str,
        version: FactFamilyVersion,
        first_tag: u8,
        duplicate_tag: u8,
    },
    MissingBundleForFamilyVersion {
        tag: u8,
        family: &'static str,
        version: FactFamilyVersion,
    },
    ActiveFromProtocolMismatch {
        tag: u8,
        family: &'static str,
        version: FactFamilyVersion,
        declared: ProtocolVersion,
        actual: ProtocolVersion,
    },
    DuplicateRouteTag {
        tag: u8,
    },
    MissingRoute {
        tag: u8,
    },
    UnmanifestedRoute {
        tag: u8,
    },
    RouteProjectorMismatch {
        tag: u8,
        expected: FactVersionProjector,
        actual: FactVersionProjector,
    },
}

/// Look up the manifest entry for one routed fact tag.
pub fn fact_version_for_tag(
    manifest: &[FactVersionManifestEntry],
    tag: u8,
) -> Option<FactVersionManifestEntry> {
    manifest.iter().copied().find(|entry| entry.tag == tag)
}

/// Look up the protocol version that first admits one routed fact tag.
pub fn active_from_protocol_for_tag(
    manifest: &[FactVersionManifestEntry],
    tag: u8,
) -> Option<ProtocolVersion> {
    fact_version_for_tag(manifest, tag).map(|entry| entry.active_from_protocol)
}

/// Validate that fact-version metadata, bundle membership, and routes agree.
///
/// This is the static guardrail behind the release manifest plan. A tag must
/// name exactly one family version, that family version's declared
/// `active_from_protocol` must match the first protocol bundle that contains it, and
/// the route table must expose the same projector label.
pub fn validate_fact_version_manifest(
    manifest: &[FactVersionManifestEntry],
    bundles: &[ProtocolBundle],
    routes: &[FactVersionRoute],
) -> Result<(), FactVersionManifestError> {
    if manifest.is_empty() {
        return Err(FactVersionManifestError::EmptyManifest);
    }
    validate_protocol_bundles(bundles)
        .map_err(|error| FactVersionManifestError::InvalidBundleTable { error })?;

    let mut entries_by_tag = BTreeMap::<u8, FactVersionManifestEntry>::new();
    let mut tags_by_family_version = BTreeMap::<(&'static str, FactFamilyVersion), u8>::new();
    for entry in manifest {
        if entries_by_tag.insert(entry.tag, *entry).is_some() {
            return Err(FactVersionManifestError::DuplicateTag { tag: entry.tag });
        }

        let key = (entry.family, entry.version);
        if let Some(first_tag) = tags_by_family_version.insert(key, entry.tag) {
            return Err(FactVersionManifestError::DuplicateFamilyVersion {
                family: entry.family,
                version: entry.version,
                first_tag,
                duplicate_tag: entry.tag,
            });
        }

        let Some(actual_active_from) = first_protocol_containing(bundles, entry.family_version())
        else {
            return Err(FactVersionManifestError::MissingBundleForFamilyVersion {
                tag: entry.tag,
                family: entry.family,
                version: entry.version,
            });
        };
        if entry.active_from_protocol != actual_active_from {
            return Err(FactVersionManifestError::ActiveFromProtocolMismatch {
                tag: entry.tag,
                family: entry.family,
                version: entry.version,
                declared: entry.active_from_protocol,
                actual: actual_active_from,
            });
        }
    }

    let mut routes_by_tag = BTreeMap::<u8, FactVersionRoute>::new();
    for route in routes {
        if routes_by_tag.insert(route.tag, *route).is_some() {
            return Err(FactVersionManifestError::DuplicateRouteTag { tag: route.tag });
        }
    }

    for entry in manifest {
        let Some(route) = routes_by_tag.get(&entry.tag).copied() else {
            return Err(FactVersionManifestError::MissingRoute { tag: entry.tag });
        };
        if entry.projector != route.projector {
            return Err(FactVersionManifestError::RouteProjectorMismatch {
                tag: entry.tag,
                expected: entry.projector,
                actual: route.projector,
            });
        }
    }

    for route in routes {
        if !entries_by_tag.contains_key(&route.tag) {
            return Err(FactVersionManifestError::UnmanifestedRoute { tag: route.tag });
        }
    }

    Ok(())
}

fn first_protocol_containing(
    bundles: &[ProtocolBundle],
    member: FamilyVersion,
) -> Option<ProtocolVersion> {
    bundles
        .iter()
        .find(|bundle| bundle.contains(member))
        .map(|bundle| bundle.protocol)
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
    pub version: FactFamilyVersion,
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
        ceiling_family_version: FactFamilyVersion,
    ) -> Result<FactFamilyVersion, WriteVersionError> {
        let writer = self
            .writers
            .iter()
            .find(|writer| writer.family == family)
            .copied()
            .ok_or(WriteVersionError::NoAuthor { family })?;
        if writer.version > ceiling_family_version {
            return Err(WriteVersionError::AboveCeiling {
                family,
                writer_version: writer.version,
                ceiling_version: ceiling_family_version,
            });
        }
        Ok(writer.version)
    }

    pub fn write_version_for_bundle(
        self,
        family: &'static str,
        ceiling_bundle: ProtocolBundle,
    ) -> Result<FactFamilyVersion, WriteVersionError> {
        let ceiling_version = ceiling_bundle.family_version(family).ok_or(
            WriteVersionError::FamilyNotInCeilingBundle {
                family,
                protocol: ceiling_bundle.protocol,
            },
        )?;
        self.write_version(family, ceiling_version)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteVersionError {
    NoAuthor {
        family: &'static str,
    },
    AboveCeiling {
        family: &'static str,
        writer_version: FactFamilyVersion,
        ceiling_version: FactFamilyVersion,
    },
    FamilyNotInCeilingBundle {
        family: &'static str,
        protocol: ProtocolVersion,
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
        active_from_protocol: ProtocolVersion,
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
    route_active_from_protocol: Option<ProtocolVersion>,
    ceiling: ProtocolVersion,
    authenticated_source: bool,
) -> IngressClassification {
    if !authenticated_source {
        return IngressClassification::Dropped(DropReason::UnauthenticatedSource);
    }
    let Some(active_from_protocol) = route_active_from_protocol else {
        return IngressClassification::Pending(PendingReason::UnknownTag);
    };
    if active_from_protocol > ceiling {
        IngressClassification::Pending(PendingReason::AboveCeiling {
            active_from_protocol,
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
    const MESSAGE: &str = "message";
    const FILE: &str = "file";
    const ADMIN: &str = "auth_admin";
    const V1_WRITER: &[FamilyWriter] = &[FamilyWriter {
        family: FAMILY,
        version: 1,
    }];
    const V2_WRITER: &[FamilyWriter] = &[FamilyWriter {
        family: FAMILY,
        version: 2,
    }];
    const PROTOCOL_1_FAMILIES: &[FamilyVersion] = &[
        FamilyVersion {
            family: MESSAGE,
            version: 1,
        },
        FamilyVersion {
            family: FILE,
            version: 1,
        },
        FamilyVersion {
            family: ADMIN,
            version: 1,
        },
    ];
    const PROTOCOL_2_FAMILIES: &[FamilyVersion] = &[
        FamilyVersion {
            family: MESSAGE,
            version: 2,
        },
        FamilyVersion {
            family: FILE,
            version: 1,
        },
        FamilyVersion {
            family: ADMIN,
            version: 1,
        },
    ];
    const PROTOCOL_3_FAMILIES: &[FamilyVersion] = &[
        FamilyVersion {
            family: MESSAGE,
            version: 2,
        },
        FamilyVersion {
            family: FILE,
            version: 2,
        },
        FamilyVersion {
            family: ADMIN,
            version: 1,
        },
    ];
    const PROTOCOL_BUNDLES: &[ProtocolBundle] = &[
        ProtocolBundle {
            protocol: 1,
            families: PROTOCOL_1_FAMILIES,
        },
        ProtocolBundle {
            protocol: 2,
            families: PROTOCOL_2_FAMILIES,
        },
        ProtocolBundle {
            protocol: 3,
            families: PROTOCOL_3_FAMILIES,
        },
    ];
    const MESSAGE_V1_PROJECTOR: FactVersionProjector =
        FactVersionProjector::new("content::message::project::Projector");
    const MESSAGE_V2_PROJECTOR: FactVersionProjector =
        FactVersionProjector::new("content::message::project::Projector");
    const FILE_V1_PROJECTOR: FactVersionProjector =
        FactVersionProjector::new("content::file::project::Projector");
    const FILE_V2_PROJECTOR: FactVersionProjector =
        FactVersionProjector::new("content::file::project::Projector");
    const ADMIN_V1_PROJECTOR: FactVersionProjector =
        FactVersionProjector::new("auth::admin::project::Projector");
    const FACT_VERSION_MANIFEST: &[FactVersionManifestEntry] = &[
        FactVersionManifestEntry {
            tag: 50,
            family: MESSAGE,
            version: 1,
            active_from_protocol: 1,
            projector: MESSAGE_V1_PROJECTOR,
        },
        FactVersionManifestEntry {
            tag: 51,
            family: MESSAGE,
            version: 2,
            active_from_protocol: 2,
            projector: MESSAGE_V2_PROJECTOR,
        },
        FactVersionManifestEntry {
            tag: 52,
            family: FILE,
            version: 1,
            active_from_protocol: 1,
            projector: FILE_V1_PROJECTOR,
        },
        FactVersionManifestEntry {
            tag: 53,
            family: FILE,
            version: 2,
            active_from_protocol: 3,
            projector: FILE_V2_PROJECTOR,
        },
        FactVersionManifestEntry {
            tag: 54,
            family: ADMIN,
            version: 1,
            active_from_protocol: 1,
            projector: ADMIN_V1_PROJECTOR,
        },
    ];
    const FACT_VERSION_ROUTES: &[FactVersionRoute] = &[
        FactVersionRoute::new(50, MESSAGE_V1_PROJECTOR),
        FactVersionRoute::new(51, MESSAGE_V2_PROJECTOR),
        FactVersionRoute::new(52, FILE_V1_PROJECTOR),
        FactVersionRoute::new(53, FILE_V2_PROJECTOR),
        FactVersionRoute::new(54, ADMIN_V1_PROJECTOR),
    ];

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
                ceiling_version: 1,
            })
        );
    }

    #[test]
    fn protocol_bundles_are_complete_family_version_sets() {
        validate_protocol_bundles(PROTOCOL_BUNDLES).expect("valid bundle table");

        let protocol_2 = bundle_for_protocol(PROTOCOL_BUNDLES, 2).expect("protocol 2 bundle");
        assert_eq!(protocol_2.family_version(MESSAGE), Some(2));
        assert_eq!(protocol_2.family_version(FILE), Some(1));
        assert_eq!(protocol_2.family_version(ADMIN), Some(1));
        assert!(protocol_2.contains(FamilyVersion {
            family: MESSAGE,
            version: 2,
        }));

        assert_eq!(
            family_version_for_protocol(PROTOCOL_BUNDLES, 3, FILE),
            Ok(2)
        );
        assert_eq!(
            family_version_for_protocol(PROTOCOL_BUNDLES, 3, "missing"),
            Err(ProtocolBundleError::MissingFamily {
                protocol: 3,
                family: "missing",
            })
        );
    }

    #[test]
    fn protocol_bundle_validation_rejects_ambiguous_or_non_monotonic_tables() {
        const DUPLICATE_FAMILIES: &[FamilyVersion] = &[
            FamilyVersion {
                family: MESSAGE,
                version: 1,
            },
            FamilyVersion {
                family: MESSAGE,
                version: 1,
            },
        ];
        let duplicate_family = [ProtocolBundle {
            protocol: 1,
            families: DUPLICATE_FAMILIES,
        }];
        assert_eq!(
            validate_protocol_bundles(&duplicate_family),
            Err(ProtocolBundleError::DuplicateFamily {
                protocol: 1,
                family: MESSAGE,
            })
        );

        const MESSAGE_REGRESSION: &[FamilyVersion] = &[
            FamilyVersion {
                family: MESSAGE,
                version: 1,
            },
            FamilyVersion {
                family: FILE,
                version: 1,
            },
        ];
        let regression = [
            ProtocolBundle {
                protocol: 1,
                families: PROTOCOL_2_FAMILIES,
            },
            ProtocolBundle {
                protocol: 2,
                families: MESSAGE_REGRESSION,
            },
        ];
        assert_eq!(
            validate_protocol_bundles(&regression),
            Err(ProtocolBundleError::FamilyVersionRegression {
                protocol: 2,
                family: MESSAGE,
                previous: 2,
                current: 1,
            })
        );

        const MESSAGE_ONLY: &[FamilyVersion] = &[FamilyVersion {
            family: MESSAGE,
            version: 2,
        }];
        let dropped = [
            ProtocolBundle {
                protocol: 1,
                families: PROTOCOL_2_FAMILIES,
            },
            ProtocolBundle {
                protocol: 2,
                families: MESSAGE_ONLY,
            },
        ];
        assert_eq!(
            validate_protocol_bundles(&dropped),
            Err(ProtocolBundleError::FamilyDropped {
                protocol: 2,
                family: ADMIN,
            })
        );
    }

    #[test]
    fn fact_version_manifest_ties_tags_to_bundle_membership_and_routes() {
        validate_fact_version_manifest(
            FACT_VERSION_MANIFEST,
            PROTOCOL_BUNDLES,
            FACT_VERSION_ROUTES,
        )
        .expect("manifest, bundles, and routes agree");

        assert_eq!(
            active_from_protocol_for_tag(FACT_VERSION_MANIFEST, 51),
            Some(2)
        );
        assert_eq!(
            fact_version_for_tag(FACT_VERSION_MANIFEST, 53).map(|entry| entry.family_version()),
            Some(FamilyVersion {
                family: FILE,
                version: 2,
            })
        );
        assert_eq!(
            active_from_protocol_for_tag(FACT_VERSION_MANIFEST, 200),
            None
        );
    }

    #[test]
    fn fact_version_manifest_validation_rejects_unsafe_edges() {
        let mut duplicate_tag = FACT_VERSION_MANIFEST.to_vec();
        duplicate_tag[1].tag = duplicate_tag[0].tag;
        assert_eq!(
            validate_fact_version_manifest(&duplicate_tag, PROTOCOL_BUNDLES, FACT_VERSION_ROUTES),
            Err(FactVersionManifestError::DuplicateTag { tag: 50 })
        );

        let mut duplicate_family_version = FACT_VERSION_MANIFEST.to_vec();
        duplicate_family_version[1].family = duplicate_family_version[0].family;
        duplicate_family_version[1].version = duplicate_family_version[0].version;
        assert_eq!(
            validate_fact_version_manifest(
                &duplicate_family_version,
                PROTOCOL_BUNDLES,
                FACT_VERSION_ROUTES,
            ),
            Err(FactVersionManifestError::DuplicateFamilyVersion {
                family: MESSAGE,
                version: 1,
                first_tag: 50,
                duplicate_tag: 51,
            })
        );

        let mut wrong_active_from = FACT_VERSION_MANIFEST.to_vec();
        wrong_active_from[1].active_from_protocol = 1;
        assert_eq!(
            validate_fact_version_manifest(
                &wrong_active_from,
                PROTOCOL_BUNDLES,
                FACT_VERSION_ROUTES
            ),
            Err(FactVersionManifestError::ActiveFromProtocolMismatch {
                tag: 51,
                family: MESSAGE,
                version: 2,
                declared: 1,
                actual: 2,
            })
        );

        let mut missing_bundle_member = FACT_VERSION_MANIFEST.to_vec();
        missing_bundle_member[1].version = 3;
        assert_eq!(
            validate_fact_version_manifest(
                &missing_bundle_member,
                PROTOCOL_BUNDLES,
                FACT_VERSION_ROUTES,
            ),
            Err(FactVersionManifestError::MissingBundleForFamilyVersion {
                tag: 51,
                family: MESSAGE,
                version: 3,
            })
        );

        let mut route_projector_mismatch = FACT_VERSION_ROUTES.to_vec();
        route_projector_mismatch[0].projector = FILE_V1_PROJECTOR;
        assert_eq!(
            validate_fact_version_manifest(
                FACT_VERSION_MANIFEST,
                PROTOCOL_BUNDLES,
                &route_projector_mismatch,
            ),
            Err(FactVersionManifestError::RouteProjectorMismatch {
                tag: 50,
                expected: MESSAGE_V1_PROJECTOR,
                actual: FILE_V1_PROJECTOR,
            })
        );

        let missing_route = &FACT_VERSION_ROUTES[1..];
        assert_eq!(
            validate_fact_version_manifest(FACT_VERSION_MANIFEST, PROTOCOL_BUNDLES, missing_route),
            Err(FactVersionManifestError::MissingRoute { tag: 50 })
        );

        let mut unmanifested_route = FACT_VERSION_ROUTES.to_vec();
        unmanifested_route.push(FactVersionRoute::new(99, MESSAGE_V1_PROJECTOR));
        assert_eq!(
            validate_fact_version_manifest(
                FACT_VERSION_MANIFEST,
                PROTOCOL_BUNDLES,
                &unmanifested_route,
            ),
            Err(FactVersionManifestError::UnmanifestedRoute { tag: 99 })
        );
    }

    #[test]
    fn received_bytes_are_pending_until_their_tag_is_ceiling_active() {
        assert_eq!(
            classify_received_fact(Some(2), 1, true),
            IngressClassification::Pending(PendingReason::AboveCeiling {
                active_from_protocol: 2,
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
