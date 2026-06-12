//! Local secret-retirement semantic adapter.
//!
//! The current local_secret_retirement wire shape is already the active
//! semantic shape. This identity adapter keeps the staged route explicit and
//! gives future versioned facts a dedicated conversion point.

use super::fact::LocalSecretRetirementFact;

pub(crate) fn adapt(
    source: LocalSecretRetirementFact,
) -> Result<LocalSecretRetirementFact, String> {
    Ok(source)
}
