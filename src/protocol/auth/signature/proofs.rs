//! Verus proofs for the `protocol::auth::signature` fact family.
//!
//! Signature facts are evidence producers. They do not prove authority over a
//! target; they prove only that the `signature_proof` offer is bound to a
//! decoded signature fact in the correct workspace scope, target fact id, and
//! signer public key.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
verus! {
pub mod verus_model {
    use vstd::prelude::*;

    pub open spec fn signature_proof_role() -> int {
        1int
    }

    pub open spec fn signature_selector(target_fact_id: int, signer_public_key: int) -> int {
        target_fact_id * 1000003int + signer_public_key
    }

    #[derive(Copy, Clone)]
    pub struct SpecSignatureFact {
        pub fact_id: int,
        pub scope: int,
        pub workspace_scope: int,
        pub workspace_id: int,
        pub target_fact_id: int,
        pub signer_public_key: int,
        pub decoded: bool,
        pub signature_verified: bool,
    }

    #[derive(Copy, Clone)]
    pub struct SpecSignatureProofOffer {
        pub owner: int,
        pub role: int,
        pub scope: int,
        pub start_key: int,
        pub end_key: int,
        pub target_fact_id: int,
        pub signer_public_key: int,
    }

    pub open spec fn signature_projector_offer(
        fact: SpecSignatureFact,
    ) -> SpecSignatureProofOffer {
        SpecSignatureProofOffer {
            owner: fact.fact_id,
            role: signature_proof_role(),
            scope: fact.workspace_scope,
            start_key: signature_selector(fact.target_fact_id, fact.signer_public_key),
            end_key: signature_selector(fact.target_fact_id, fact.signer_public_key),
            target_fact_id: fact.target_fact_id,
            signer_public_key: fact.signer_public_key,
        }
    }

    pub open spec fn valid_signature_proof_offer(
        offer: SpecSignatureProofOffer,
        fact: SpecSignatureFact,
        workspace_id: int,
        target_fact_id: int,
        signer_public_key: int,
    ) -> bool {
        fact.decoded
            && fact.signature_verified
            && fact.workspace_id == workspace_id
            && fact.target_fact_id == target_fact_id
            && fact.signer_public_key == signer_public_key
            && fact.scope == fact.workspace_scope
            && offer.owner == fact.fact_id
            && offer.role == signature_proof_role()
            && offer.scope == fact.workspace_scope
            && offer.start_key == signature_selector(target_fact_id, signer_public_key)
            && offer.end_key == signature_selector(target_fact_id, signer_public_key)
            && offer.target_fact_id == target_fact_id
            && offer.signer_public_key == signer_public_key
    }

    pub proof fn theorem_signature_projector_offer_is_valid(
        fact: SpecSignatureFact,
        workspace_id: int,
        target_fact_id: int,
        signer_public_key: int,
    )
        requires
            fact.decoded,
            fact.signature_verified,
            fact.workspace_id == workspace_id,
            fact.target_fact_id == target_fact_id,
            fact.signer_public_key == signer_public_key,
            fact.scope == fact.workspace_scope,
        ensures
            valid_signature_proof_offer(
                signature_projector_offer(fact),
                fact,
                workspace_id,
                target_fact_id,
                signer_public_key,
            )
    {
    }
}
}
