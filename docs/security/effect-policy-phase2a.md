# Effect policy Phase 2A: destructive computer control

## Scope

Phase 2A adds one bounded semantic boundary: destructive operations of the
registered `computer_use` tool. It does not establish a generic mutability
metadata framework for arbitrary `ToolRegistry` entries.

The canonical action classification remains the closed `_ACTIONS` table in
`tools/computer_use/tool.py`. Phase 2A reads that table rather than maintaining
a second action list:

| Classification | Actions |
|---|---|
| Mutating `computer_control` on resource `computer` | `click`, `double_click`, `right_click`, `middle_click`, `drag`, `scroll`, `type`, `key`, `set_value`, `focus_app` |
| Existing compatibility behavior (no Phase-2A semantic request) | `capture`, `wait`, `list_apps`, `list_windows` |

A missing, unknown, non-string, or empty action, malformed `destructive`
metadata, or a classifier exception denies the call before handler execution.
An empty valid effect policy otherwise preserves existing behavior.

## Enforcement and approval flow

Model-originated calls are still normalized and rewritten before authorization.
The `tool_call` bridge unwraps to `computer_use`, so authorization sees the
underlying operation and final arguments.

`ToolRegistry.dispatch` is the final checked boundary for this surface. This is
intentional: it covers normal `handle_function_call` execution, bridge-unwrapped
calls, direct registry dispatch, and `PluginContext.dispatch_tool`. A denied call
returns an effect-policy error before the registered handler can construct or
start a backend, create process/cache state, or send desktop input.

The new semantic identities are:

- `EffectKind.COMPUTER_CONTROL` (`computer_control`)
- `ResourceKind.COMPUTER` (`computer`)

They use the Phase-1 deny-first and approval semantics:

- `deny_effects: [computer_control]` is non-bypassable;
- `require_approval_effects: [computer_control]` requests ordinary scoped
  approval in an interactive session;
- approval-required unattended execution is denied;
- the existing approval-bypass mode may bypass an ordinary effect approval but
  never an explicit deny;
- an invalid policy denies destructive actions while the four compatibility
  actions remain available.

The existing computer-use approval and hard-block systems remain separate
independent defenses. Effect-policy approval does not auto-approve those gates,
and their approvals do not override effect-policy denial.

## Permit and registration binding

For `computer_use`, a one-shot effect permit binds:

- canonical tool name;
- normalized action, security classification, and mutability;
- complete final-argument digest;
- effective task, session, and tool-call identities;
- live policy and execution-context fingerprint;
- an immutable dispatch identity containing the exact active `ToolEntry`,
  handler, async mode, and monotonic registration-slot generation observed
  before policy and approval evaluation.

Permit consumption is deferred from `model_tools` to `ToolRegistry.dispatch`,
where the active registration can be compared with the bound identity. A
replacement after issuance invalidates the permit and forces live
reauthorization. A replacement during direct policy or approval evaluation is
rejected without executing either handler. Registration removal/re-registration,
an ABA restore, in-place handler substitution, and a registration change during
permit issuance are also detected. The final identity check and captured handler
selection establish the execution lease; the global registry lock is released
before invoking tool code.

This is a per-slot generation and handler binding, not a claim that a tool name
or toolset is a security identity. It prevents same-name replacement or restore
from inheriting an earlier approval.

Session/permanent effect approvals are also keyed by a per-registration random
scope and the captured handler identity. A replacement, restoration, or
in-place handler substitution therefore must obtain a fresh human decision
rather than reuse the previous handler's cached approval. The scope is
process-local so persisted approval cannot outlive the exact registration
instance it covered.

## Failure behavior

Destructive `computer_use` fails closed when:

- action classification is missing, malformed, unknown, or raises;
- the effect policy is malformed or cannot be evaluated;
- required approval is denied or unavailable;
- final arguments, task/session/call identity, policy/context fingerprint, or bound
  registration do not match the permit;
- registry-level authorization raises;
- the registration changes during authorization.

Read-only compatibility actions preserve the Phase-1 invalid-policy behavior.
Handler errors after successful authorization retain the normal registry result
contract.

## Explicit exclusions

Phase 2A does **not** govern or claim complete coverage for:

- browser tools, arbitrary CDP, `browser_exec`, or browser-side script effects;
- generic MCP and connector operations;
- native Codex app-server execution or file operations;
- ACP-native or direct filesystem callbacks;
- policy-control UI writes and cron/background-script policy;
- arbitrary in-process Python, plugin callbacks outside this tool dispatch, or
  subprocess descendants;
- `computer_use` backend implementation effects for the four compatibility
  actions;
- operating-system state changes or TOCTOU after the approved handler begins.

Accordingly, effect-policy coverage remains partial. The Phase-1 remaining-gap
list still applies except for the destructive `computer_use` boundary described
here.
