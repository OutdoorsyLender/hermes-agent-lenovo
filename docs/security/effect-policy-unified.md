# Unified Effect-Policy Boundary

This phase extends the semantic effect policy introduced in Phase 1 and the
`computer_use` registration binding introduced in Phase 2A. It provides one
application-level authorization contract for registered tools, connector
transport, MCP calls, shell bangs, cron scripts, and native Codex turns.

It is an application admission control. It is **not** an operating-system
sandbox and does not claim to mediate subprocess descendants after admission.

## Security contract

Every registry entry has an immutable `EffectDescriptor` with one of four
modes:

- `read_only`: explicitly declared compatibility/read behavior;
- `static`: a fixed set of semantic effects;
- `conditional`: a host-owned resolver classifies the final arguments;
- `opaque`: unresolved authority that is conservatively treated as process
  execution with unknown mutability.

Missing registration metadata becomes `opaque`; it never means read-only.
Remote descriptions, schemas, HTTP verbs, and dynamic schema overrides are not
security authorities.

The normal model path authorizes post-middleware arguments and relays a one-use
permit to the final registry or connector boundary. The final boundary binds:

- tool name and canonical argument digest;
- task, session, and tool-call identities;
- live policy and execution-context fingerprint;
- normalized semantic-effect and canonical-target digest;
- registry scope, generation, handler identity, and effect descriptor.

Permit replay, argument drift, target drift, policy/context changes, descriptor
replacement, handler replacement, and registration replacement force fresh
authorization or deny. Registered tools are checked at `ToolRegistry.dispatch`,
so direct registry calls and `PluginContext.dispatch_tool` do not bypass the
policy.

Handlers that have a second approval or preparation phase revalidate the bound
admission immediately before their irreversible operation. This applies to
terminal execution, `execute_code`, native file write/patch, and
`process_manage`. A direct internal caller without a bound admission receives a
fresh live decision instead of an implicit bypass.

## Classified surfaces

- Existing Phase 1 adapters remain conditional descriptors for `write_file`,
  `patch`, `terminal`, `execute_code`, `process_manage`, `memory`,
  `skill_manage`, `setup_mcp`, and `computer_use`.
- `read_file` and `search_files` are explicitly read-only.
- Unknown built-in or plugin registrations are opaque by default.
- MCP tools default to `mcp_mutate`. Exact `readOnlyHint is True` maps to
  `mcp_read` only when the operator explicitly sets
  `trust_read_only_hints: true` for that server. Plugin-direct MCP calls use
  the same host-captured classification and effect policy.
- Connector calls are opaque until the connector protocol carries trusted,
  versioned effect metadata. The final transport checks the exact connector
  name and arguments before the remote call.
- `cronjob_manage` treats listing as read-only, schedule changes as Hermes
  configuration mutation, and immediate runs as opaque process execution.
- `computer_use` treats focus-changing options such as `bring_to_front` and
  `focus_app(raise_window=true)` as control effects even when the base action is
  otherwise observational.

## Direct execution carriers

The following paths do not naturally pass through the registry and therefore
have explicit final checks:

- `!command` authorizes the exact command before `Popen`; approval import or
  runtime failures deny.
- Cron pre-run and no-agent scripts authorize opaque unattended process
  execution immediately before `Popen`.
- Native Codex app-server turns authorize an opaque carrier before starting the
  app server or issuing `turn/start`.
- Connector transport consumes a bound permit or performs live opaque
  authorization before `run_remote`.

Pre-tool plugin callback exceptions now produce a block directive, matching the
existing fail-closed timeout behavior. Process actions require the exact owning
task when an owner is recorded; handoff remains the explicit transfer path.

## Policy behavior

An empty valid effect policy preserves compatibility. An invalid policy allows
only explicitly classified read-only requests and denies mutating, opaque, or
unresolved requests. When any configured deny or approval-required effect could
be reached through an opaque carrier, the carrier is denied or requires exact
one-operation approval. Unattended approval requirements deny rather than
prompt.

Approval categories are not effect permits. Permits are one-use and bind the
exact normalized operation and payload identity.

## Bounded guarantee and limitations

The guarantee is authorization at the last in-process admission point. It does
not provide OS confinement. After an allowed terminal, interpreter, browser,
plugin, MCP, connector, cron, or native Codex carrier starts, arbitrary native
code and subprocess descendants may use direct filesystem, process, credential,
or network APIs without another Hermes callback. Aliases, functions, scripts,
PATH resolution, encoded interpreter payloads, and shell expansion therefore
remain opaque rather than being represented as semantically resolved.

Strong descendant guarantees require a broker or OS sandbox with platform
confinement and handle-relative, no-follow filesystem operations. The in-process
file revalidation materially narrows target substitution but does not claim to
eliminate the final syscall-level race.

Registry entries bind a captured handler at admission; they do not freeze the
handler's mutable globals, closures, imported modules, or arbitrary plugin
Python. Plugins are trusted in-process code outside the tool-dispatch boundary.

Policy snapshots are revalidated at final admission, but configuration storage
does not yet expose a single atomic monotonic epoch shared with every writer.
Already admitted child processes follow launch-authorization semantics and are
not revoked automatically when policy changes.

## Qualification targets

Focused qualification covers:

- direct registry and plugin dispatch of migrated, opaque, static, and
  read-only descriptors;
- one-use permit relay and replay denial;
- argument, policy, target, handler, registration, and descriptor drift;
- MCP read/mutate parity and plugin-direct MCP calls;
- connector transport denial before remote execution;
- bang, cron, and native Codex denial before process start;
- process owner enforcement;
- plugin callback exceptions;
- `computer_use` focus side effects;
- continued explicit read-only file inspection under restrictive or invalid
  policy.

Platform-specific baseline failures and skips must be reported separately from
regressions introduced by this phase.
