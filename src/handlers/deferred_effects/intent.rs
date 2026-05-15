//! Deferred effect intent layouts that replace target-side protocol work queues.
//!
//! These intents name exact facts/events and carry deterministic idempotence
//! keys. Handlers that execute them must use `HandlerContext` fact lookup for
//! payloads instead of scanning protocol tables.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

pub type HandlerId = [u8; 32];

pub const ADMIT_RECEIVED_FACT: &str = "admit_received_fact";
pub const HANDLE_SYNC_EVENT: &str = "handle_sync_event";
pub const MATERIALIZE_KEY_REQUEST: &str = "materialize_key_request";
pub const UNWRAP_KEY_WRAP: &str = "unwrap_key_wrap";
pub const RECONCILE_KEY_WRAPS: &str = "reconcile_key_wraps";
pub const SYNC_INDEX_REMOVE: &str = "sync_index_remove";
pub const PURGE_EVENT: &str = "purge_event";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmitReceivedFact {
    pub source_id: HandlerId,
    pub canonical_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedEventIntent {
    pub workspace_id: HandlerId,
    pub event_id: HandlerId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEventIntent {
    pub connection_id: HandlerId,
    pub event_id: HandlerId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleEventIntent {
    pub event_id: HandlerId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileTrigger {
    RecipientKey,
    Frontier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconcileKeyWraps {
    pub workspace_id: HandlerId,
    pub trigger: ReconcileTrigger,
    pub trigger_id: HandlerId,
}

pub fn admit_received_fact_intent(input: AdmitReceivedFact) -> Intent {
    let mut payload = Vec::new();
    payload.push(1);
    payload.extend_from_slice(&input.source_id);
    put_bytes(&mut payload, &input.canonical_bytes);

    Intent::new(
        IntentKind::new(ADMIT_RECEIVED_FACT).expect("valid admit_received_fact intent kind"),
        IntentExecution::Deferred,
        received_fact_key(input.source_id, &input.canonical_bytes),
        payload,
    )
}

pub fn decode_admit_received_fact(intent: &Intent) -> Result<AdmitReceivedFact, String> {
    expect_kind(intent, ADMIT_RECEIVED_FACT)?;
    let mut reader = Reader::new(&intent.payload);
    reader.expect_version()?;
    let source_id = reader.id()?;
    let canonical_bytes = reader.bytes()?.to_vec();
    reader.finish()?;
    if intent.key != received_fact_key(source_id, &canonical_bytes) {
        return Err("admit_received_fact key does not match payload".to_string());
    }
    Ok(AdmitReceivedFact {
        source_id,
        canonical_bytes,
    })
}

pub fn handle_sync_event_intent(input: ConnectionEventIntent) -> Intent {
    connection_event_intent(HANDLE_SYNC_EVENT, input)
}

pub fn decode_handle_sync_event(intent: &Intent) -> Result<ConnectionEventIntent, String> {
    decode_connection_event(intent, HANDLE_SYNC_EVENT)
}

pub fn materialize_key_request_intent(input: SingleEventIntent) -> Intent {
    single_event_intent(MATERIALIZE_KEY_REQUEST, input)
}

pub fn decode_materialize_key_request(intent: &Intent) -> Result<SingleEventIntent, String> {
    decode_single_event(intent, MATERIALIZE_KEY_REQUEST)
}

pub fn unwrap_key_wrap_intent(input: SingleEventIntent) -> Intent {
    single_event_intent(UNWRAP_KEY_WRAP, input)
}

pub fn decode_unwrap_key_wrap(intent: &Intent) -> Result<SingleEventIntent, String> {
    decode_single_event(intent, UNWRAP_KEY_WRAP)
}

pub fn sync_index_remove_intent(input: ScopedEventIntent) -> Intent {
    scoped_event_intent(SYNC_INDEX_REMOVE, input)
}

pub fn decode_sync_index_remove(intent: &Intent) -> Result<ScopedEventIntent, String> {
    decode_scoped_event(intent, SYNC_INDEX_REMOVE)
}

pub fn purge_event_intent(input: ScopedEventIntent) -> Intent {
    scoped_event_intent(PURGE_EVENT, input)
}

pub fn decode_purge_event(intent: &Intent) -> Result<ScopedEventIntent, String> {
    decode_scoped_event(intent, PURGE_EVENT)
}

pub fn reconcile_key_wraps_intent(input: ReconcileKeyWraps) -> Intent {
    let mut payload = Vec::with_capacity(66);
    payload.push(1);
    payload.extend_from_slice(&input.workspace_id);
    payload.push(input.trigger.to_byte());
    payload.extend_from_slice(&input.trigger_id);

    Intent::new(
        IntentKind::new(RECONCILE_KEY_WRAPS).expect("valid reconcile_key_wraps intent kind"),
        IntentExecution::Deferred,
        reconcile_key(input.workspace_id, input.trigger, input.trigger_id),
        payload,
    )
}

pub fn decode_reconcile_key_wraps(intent: &Intent) -> Result<ReconcileKeyWraps, String> {
    expect_kind(intent, RECONCILE_KEY_WRAPS)?;
    if intent.payload.len() != 66 || intent.payload[0] != 1 {
        return Err("reconcile_key_wraps payload is malformed".to_string());
    }
    let workspace_id = intent.payload[1..33].try_into().unwrap();
    let trigger = ReconcileTrigger::from_byte(intent.payload[33])?;
    let trigger_id = intent.payload[34..66].try_into().unwrap();
    if intent.key != reconcile_key(workspace_id, trigger, trigger_id) {
        return Err("reconcile_key_wraps key does not match payload".to_string());
    }
    Ok(ReconcileKeyWraps {
        workspace_id,
        trigger,
        trigger_id,
    })
}

fn connection_event_intent(kind: &str, input: ConnectionEventIntent) -> Intent {
    let mut payload = Vec::with_capacity(65);
    payload.push(1);
    payload.extend_from_slice(&input.connection_id);
    payload.extend_from_slice(&input.event_id);
    Intent::new(
        IntentKind::new(kind).expect("valid connection event intent kind"),
        IntentExecution::Deferred,
        pair_key(input.connection_id, input.event_id),
        payload,
    )
}

fn decode_connection_event(intent: &Intent, kind: &str) -> Result<ConnectionEventIntent, String> {
    expect_kind(intent, kind)?;
    if intent.payload.len() != 65 || intent.payload[0] != 1 {
        return Err(format!("{kind} payload is malformed"));
    }
    let connection_id = intent.payload[1..33].try_into().unwrap();
    let event_id = intent.payload[33..65].try_into().unwrap();
    if intent.key != pair_key(connection_id, event_id) {
        return Err(format!("{kind} key does not match payload"));
    }
    Ok(ConnectionEventIntent {
        connection_id,
        event_id,
    })
}

fn scoped_event_intent(kind: &str, input: ScopedEventIntent) -> Intent {
    let mut payload = Vec::with_capacity(65);
    payload.push(1);
    payload.extend_from_slice(&input.workspace_id);
    payload.extend_from_slice(&input.event_id);
    Intent::new(
        IntentKind::new(kind).expect("valid scoped event intent kind"),
        IntentExecution::Deferred,
        pair_key(input.workspace_id, input.event_id),
        payload,
    )
}

fn decode_scoped_event(intent: &Intent, kind: &str) -> Result<ScopedEventIntent, String> {
    expect_kind(intent, kind)?;
    if intent.payload.len() != 65 || intent.payload[0] != 1 {
        return Err(format!("{kind} payload is malformed"));
    }
    let workspace_id = intent.payload[1..33].try_into().unwrap();
    let event_id = intent.payload[33..65].try_into().unwrap();
    if intent.key != pair_key(workspace_id, event_id) {
        return Err(format!("{kind} key does not match payload"));
    }
    Ok(ScopedEventIntent {
        workspace_id,
        event_id,
    })
}

fn single_event_intent(kind: &str, input: SingleEventIntent) -> Intent {
    let mut payload = Vec::with_capacity(33);
    payload.push(1);
    payload.extend_from_slice(&input.event_id);
    Intent::new(
        IntentKind::new(kind).expect("valid single event intent kind"),
        IntentExecution::Deferred,
        input.event_id,
        payload,
    )
}

fn decode_single_event(intent: &Intent, kind: &str) -> Result<SingleEventIntent, String> {
    expect_kind(intent, kind)?;
    if intent.payload.len() != 33 || intent.payload[0] != 1 {
        return Err(format!("{kind} payload is malformed"));
    }
    let event_id = intent.payload[1..33].try_into().unwrap();
    if intent.key != event_id {
        return Err(format!("{kind} key does not match payload"));
    }
    Ok(SingleEventIntent { event_id })
}

fn expect_kind(intent: &Intent, kind: &str) -> Result<(), String> {
    if intent.kind.as_str() != kind {
        return Err(format!("expected {kind} intent"));
    }
    if intent.execution != IntentExecution::Deferred {
        return Err(format!("{kind} intent must be deferred"));
    }
    Ok(())
}

fn pair_key(left: HandlerId, right: HandlerId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&left);
    key.extend_from_slice(&right);
    key
}

fn reconcile_key(
    workspace_id: HandlerId,
    trigger: ReconcileTrigger,
    trigger_id: HandlerId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(65);
    key.extend_from_slice(&workspace_id);
    key.push(trigger.to_byte());
    key.extend_from_slice(&trigger_id);
    key
}

fn received_fact_key(source_id: HandlerId, canonical_bytes: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"admit_received_fact");
    hasher.update(&source_id);
    hasher.update(&(canonical_bytes.len() as u64).to_be_bytes());
    hasher.update(canonical_bytes);
    hasher.finalize().as_bytes().to_vec()
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

impl ReconcileTrigger {
    fn to_byte(self) -> u8 {
        match self {
            Self::RecipientKey => 1,
            Self::Frontier => 2,
        }
    }

    fn from_byte(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::RecipientKey),
            2 => Ok(Self::Frontier),
            _ => Err("unknown reconcile trigger".to_string()),
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_version(&mut self) -> Result<(), String> {
        match self.take(1)?[0] {
            1 => Ok(()),
            _ => Err("unsupported effect intent payload version".to_string()),
        }
    }

    fn id(&mut self) -> Result<HandlerId, String> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as usize;
        self.take(len)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "effect intent payload length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated effect intent payload".to_string());
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("effect intent payload has trailing bytes".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_received_fact_intent_uses_content_bound_key() {
        let input = AdmitReceivedFact {
            source_id: [1; 32],
            canonical_bytes: b"canonical event bytes".to_vec(),
        };
        let intent = admit_received_fact_intent(input.clone());

        assert_eq!(decode_admit_received_fact(&intent).unwrap(), input);
        assert_ne!(
            intent.key,
            admit_received_fact_intent(AdmitReceivedFact {
                source_id: [1; 32],
                canonical_bytes: b"other bytes".to_vec(),
            })
            .key
        );
    }

    #[test]
    fn replacement_effect_intents_round_trip_stable_keys() {
        let scoped = ScopedEventIntent {
            workspace_id: [1; 32],
            event_id: [2; 32],
        };
        let connection = ConnectionEventIntent {
            connection_id: [3; 32],
            event_id: [4; 32],
        };
        let single = SingleEventIntent { event_id: [5; 32] };

        assert_eq!(
            decode_handle_sync_event(&handle_sync_event_intent(connection.clone())).unwrap(),
            connection
        );
        assert_eq!(
            decode_sync_index_remove(&sync_index_remove_intent(scoped.clone())).unwrap(),
            scoped
        );
        assert_eq!(
            decode_purge_event(&purge_event_intent(scoped.clone())).unwrap(),
            scoped
        );
        assert_eq!(
            decode_materialize_key_request(&materialize_key_request_intent(single.clone()))
                .unwrap(),
            single
        );
        assert_eq!(
            decode_unwrap_key_wrap(&unwrap_key_wrap_intent(single.clone())).unwrap(),
            single
        );
    }

    #[test]
    fn reconcile_intent_keys_by_scope_trigger_and_target() {
        let input = ReconcileKeyWraps {
            workspace_id: [1; 32],
            trigger: ReconcileTrigger::RecipientKey,
            trigger_id: [2; 32],
        };
        let intent = reconcile_key_wraps_intent(input.clone());

        assert_eq!(decode_reconcile_key_wraps(&intent).unwrap(), input);
        assert_ne!(
            intent.key,
            reconcile_key_wraps_intent(ReconcileKeyWraps {
                trigger: ReconcileTrigger::Frontier,
                ..input
            })
            .key
        );
    }
}
