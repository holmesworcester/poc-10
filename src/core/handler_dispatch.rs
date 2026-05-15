//! Intent handler contract.

use crate::core::facts::Fact;
use crate::core::intents::Intent;

#[derive(Debug, Default)]
pub struct HandlerContext;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandlerOutput {
    pub facts: Vec<Fact>,
    pub intents: Vec<Intent>,
}

impl HandlerOutput {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fact(mut self, fact: Fact) -> Self {
        self.facts.push(fact);
        self
    }

    pub fn intent(mut self, intent: Intent) -> Self {
        self.intents.push(intent);
        self
    }
}

pub trait IntentHandler {
    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::FactScope;
    use crate::core::intents::{IntentExecution, IntentKind};

    #[test]
    fn handler_output_feeds_facts_and_intents_back_to_core() {
        let fact = Fact::new(FactScope::Local, 7, b"bytes".to_vec());
        let intent = Intent::new(
            IntentKind::new("followup").unwrap(),
            IntentExecution::Deferred,
            b"k",
            b"p",
        );
        let output = HandlerOutput::new().fact(fact).intent(intent);

        assert_eq!(output.facts.len(), 1);
        assert_eq!(output.intents.len(), 1);
    }
}
