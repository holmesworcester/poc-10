# Crux Recommendations

Superseded by [plan.md](plan.md) and [RULES.md](RULES.md).

The retained decisions are:

- generic Crux command driving belongs in `core`
- protocol-specific CLI/effect vocabulary belongs under `protocol`
- projectors are row-only
- actors own queued work, protocol decisions, and IO effects
- shell-flow transcript tests are useful for app-runner behavior
- black-box CLI/network tests remain the functional proof

Historical experiment details remain in git history.
