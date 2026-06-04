//! Adapt contract for fact pipeline stages.

/// Adapt an authenticated source value into the semantic value projected at the
/// active head version.
pub trait Adapter {
    type Source;
    type Semantic;

    fn adapt(source: Self::Source) -> Result<Self::Semantic, String>;
}
