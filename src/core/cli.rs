//! Generic CLI registry runner.
//!
//! Core owns no command names and no protocol behavior. It only provides the
//! small dispatch shape needed by a binary: a CLI command advertises its name,
//! usage, and help text, and the runner calls the matching function with a
//! caller-owned context. The context is where protocol code can keep a store,
//! workers, TCP helpers, or anything else it needs; this file never imports
//! those concepts.
//!
//! The important invariant is locality. If a command's parser, help text, or
//! formatting changes, that change should happen in the module that exported
//! the command spec. This runner merely rejects duplicate names, reports
//! unknown CLI commands with the registry's usage lines, and returns text lines for
//! the binary to print.

/// Positional arguments passed to a command after its command name.
#[derive(Debug, Clone, Copy)]
pub struct CliArgs<'a> {
    values: &'a [String],
}

impl<'a> CliArgs<'a> {
    pub const fn new(values: &'a [String]) -> Self {
        Self { values }
    }

    pub fn values(self) -> &'a [String] {
        self.values
    }

    pub fn get(self, index: usize) -> Option<&'a str> {
        self.values.get(index).map(String::as_str)
    }

    pub fn require_len(self, expected: usize, usage: &str) -> Result<(), String> {
        if self.values.len() == expected {
            Ok(())
        } else {
            Err(usage.to_string())
        }
    }

    pub fn parse_positive_usize(self, index: usize, usage: &str) -> Result<usize, String> {
        let value = self.get(index).ok_or_else(|| usage.to_string())?;
        let parsed = value.parse::<usize>().map_err(|_| usage.to_string())?;
        if parsed == 0 {
            return Err(usage.to_string());
        }
        Ok(parsed)
    }
}

/// Text returned by a command for the binary to print.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CliOutput {
    pub lines: Vec<String>,
}

impl CliOutput {
    pub fn lines(lines: Vec<String>) -> Self {
        Self { lines }
    }

    pub fn line(line: impl Into<String>) -> Self {
        Self {
            lines: vec![line.into()],
        }
    }
}

/// One command exported by a protocol or module.
#[derive(Clone, Copy)]
pub struct CliCommand<C> {
    pub name: &'static str,
    pub usage: &'static str,
    pub help: &'static str,
    pub run: for<'a> fn(&mut C, CliArgs<'a>) -> Result<CliOutput, String>,
}

/// Dispatch argv to one of the supplied command specs.
pub fn run<C>(
    commands: &[CliCommand<C>],
    context: &mut C,
    args: &[String],
) -> Result<CliOutput, String> {
    validate_command_names(commands)?;
    let Some(command_name) = args.first() else {
        return Err(usage(commands, "missing command"));
    };
    let Some(command) = commands.iter().find(|command| command.name == command_name) else {
        return Err(usage(
            commands,
            &format!("unknown command `{command_name}`"),
        ));
    };
    (command.run)(context, CliArgs::new(&args[1..]))
        .map_err(|err| format!("{}: {err}", command.name))
}

fn validate_command_names<C>(commands: &[CliCommand<C>]) -> Result<(), String> {
    for (index, left) in commands.iter().enumerate() {
        if commands[index + 1..]
            .iter()
            .any(|right| right.name == left.name)
        {
            return Err(format!("duplicate CLI command `{}`", left.name));
        }
    }
    Ok(())
}

pub fn usage<C>(commands: &[CliCommand<C>], reason: &str) -> String {
    let mut lines = vec![reason.to_string(), "usage:".to_string()];
    for command in commands {
        lines.push(format!("  match --db PATH {}", command.usage));
    }
    lines.join("\n")
}
