use crate::core::facts::FactId;

pub const MAX_REFS: usize = 16;
pub const EMPTY_ROLE: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootRef {
    pub role: u32,
    pub index: u32,
    pub target_fact_id: FactId,
}

impl RootRef {
    pub const EMPTY: Self = Self {
        role: EMPTY_ROLE,
        index: 0,
        target_fact_id: [0; 32],
    };

    pub fn new(role: u32, index: u32, target_fact_id: FactId) -> Result<Self, String> {
        let edge = Self {
            role,
            index,
            target_fact_id,
        };
        if edge.is_empty() {
            return Err("root ref cannot be empty".to_string());
        }
        if role == EMPTY_ROLE {
            return Err("root ref role 0 is reserved for empty slots".to_string());
        }
        if target_fact_id == [0; 32] {
            return Err("root ref target cannot be zero".to_string());
        }
        Ok(edge)
    }

    pub fn is_empty(&self) -> bool {
        self.role == EMPTY_ROLE && self.index == 0 && self.target_fact_id == [0; 32]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootFact {
    pub family: u32,
    pub version: u32,
    pub created_at_ms: u64,
    pub refs: Vec<RootRef>,
}

impl RootFact {
    pub fn ref_by_role_index(&self, role: u32, index: u32) -> Option<RootRef> {
        self.refs
            .iter()
            .copied()
            .find(|edge| edge.role == role && edge.index == index)
    }

    pub fn workspace_id(&self) -> Option<FactId> {
        self.ref_by_role_index(super::roles::WORKSPACE, 0)
            .map(|edge| edge.target_fact_id)
    }
}

pub fn validate_refs(refs: &[RootRef]) -> Result<(), String> {
    if refs.len() > MAX_REFS {
        return Err(format!("root has {} refs, max is {MAX_REFS}", refs.len()));
    }

    let mut previous: Option<(u32, u32)> = None;
    for edge in refs {
        if edge.is_empty() {
            return Err("root semantic refs must not contain empty slots".to_string());
        }
        if edge.role == EMPTY_ROLE {
            return Err("root ref role 0 is reserved for empty slots".to_string());
        }
        if edge.target_fact_id == [0; 32] {
            return Err("root ref target cannot be zero".to_string());
        }

        let key = (edge.role, edge.index);
        if let Some(previous) = previous {
            if key == previous {
                return Err("root has duplicate (role,index) ref".to_string());
            }
            if key < previous {
                return Err("root refs must be sorted by (role,index)".to_string());
            }
        }
        previous = Some(key);
    }
    Ok(())
}
