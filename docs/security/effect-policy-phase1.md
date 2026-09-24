# Effect policy phase 1

> Phase 2A subsequently migrates destructive `computer_use` actions at the
> final registry boundary. See [effect-policy-phase2a.md](effect-policy-phase2a.md).

## Decision-flow map

Model-originated tool calls normally pass through request middleware, execution
middleware, plugin argument rewriting, and then
`agent.tool_executor._dispatch_authorized_once`. Registered tools subsequently
enter `model_tools.handle_function_call` and `ToolRegistry.dispatch`. Inline,
context-engine, memory-provider, and delegation tools bypass the registry but
not the agent seam. Direct/legacy callers of `handle_function_call` bypass the
agent seam.

Command approval is a separate terminal-specific evaluator. Its hardline and
`approvals.deny` floors run before allowlists, approval mode, or YOLO. Other
mutation paths—including native file tools, `execute_code`, process stdin,
computer use, ACP edits, Codex app-server requests, MCP, connectors, and direct
plugin/internal subprocess calls—previously had independent or no equivalent
semantic evaluation.

Phase 1 therefore uses two final-argument enforcement seams:

1. `agent.tool_executor._dispatch_authorized_once`, after every permitted
   argument rewrite and final JSON-schema coercion, before any agent-managed
   dispatch.
2. The innermost dispatch callback in `model_tools._execute_tool`, after direct
   callers' execution middleware and before registry or connector dispatch.

After enforcing the live profile policy, the agent seam asks the policy runtime
to issue a registry-backed one-shot permit. The permit binds a random attempt ID,
canonical tool name, final-argument digest, task ID, and tool-call ID. Validation
and consumption are one locked operation. Permits also bind a fingerprint of the
live semantic policy and approval/execution context; any policy or bypass-context
change forces inner-seam reauthorization. The
issuer accepts no caller-supplied policy, so passing an empty policy cannot mint
a permit. A forged, rewritten,
replayed, coerced after authorization, or differently identified call is
evaluated again. Argument shapes
that cannot be encoded without loss receive no permit and are re-evaluated at
the innermost seam.

## Canonical model

`tools.effect_policy` defines:

- semantic filesystem, Git, process, Hermes-control, and external-system effect
  kinds;
- resource kinds;
- actor/profile/session/execution and parent-operation provenance;
- source, destination, canonical path, and Git common-directory identities;
- `ALLOW`, `REQUIRE_APPROVAL`, `REQUIRE_HUMAN_APPROVAL`, and `DENY`;
- a deny-first lattice in which explicit semantic denies and protected-resource
  matches cannot be bypassed by approval mode, YOLO, unattended auto-approval,
  or delegated-child metadata.

Filesystem comparison normalizes Windows drive/UNC/extended paths, conservatively
case-folds native macOS paths throughout target, active-config, and repository
identity comparisons, and checks
both lexical absolute and canonical/reparse-resolved identities. Git identity is
the resolved common directory, not a repository basename or the current
working directory. Copy and move operations evaluate source and destination
with their distinct read/mutation semantics. Symlink and junction creation
mutate their destination. A protected subdirectory does not implicitly protect
every worktree sharing its repository identity; repository-wide identity is
derived only when the configured protected root is the repository root.
Repository-wide protection also covers the resolved Git common directory itself
(including refs, config, objects, and linked-worktree metadata). A failed Git
identity lookup is distinguished from a path proven not to be in a repository;
unknown identity fails closed when repository-wide protection is active.

An unresolvable possible protected filesystem/repository mutation—including
opaque command, code-execution, and process-input authority—requires a fresh
one-operation human approval. Unrelated typed resources such as process control
and memory/skill records do not inherit a filesystem-root gate merely because
they have no filesystem target. In unattended execution an unresolved protected
mutation is denied. This prompt ignores YOLO, mode-off, and persisted
session/permanent approvals.

Ordinary semantic approvals display redacted final arguments and are persisted,
when the user chooses that existing approval mode, only under a key bound to the
tool, policy reason, and exact final-argument digest.
Active and managed config classification treats removal of command deny floors and disabling
destructive confirmation settings (including default-enabled settings omitted
from the current raw file) as bypass enablement, in addition to YOLO,
mode-off, unattended approval, allowlist, and effect-policy changes. Every
mutation of the managed `config.yaml` is classified conservatively as config,
approval-policy, and bypass-enablement authority because removing an overlay may
reveal weaker user-layer values.

## Runtime policy

The profile setting is additive and defaults to no behavior change:

```yaml
security:
  effect_policy:
    protected_roots: []
    deny_effects: []
    require_approval_effects: []
```

A malformed configured policy denies migrated mutations while preserving
read-only requests. Both user and managed configuration layers—including every
explicit field type, effect name, and protected-root value—are validated before
fail-open/default merge behavior can hide active YAML parse failures, explicit
null or wrong-typed policy nodes, unknown effects, invalid roots, or unknown
policy keys.
Protected roots must use host-native absolute syntax;
drive-relative/root-relative and foreign-platform spellings are rejected. Empty
default rules short-circuit before target resolution.
Existing terminal and file-tool guards remain in place as defense in depth.

## Phase-1 migration coverage

| Boundary | Phase-1 representation |
|---|---|
| `write_file` | create+write or replace+truncate+write with task-CWD-resolved target; dangling symlink/reparse referents are classified as creates; creation under a missing parent also emits create-directory; active `config.yaml` writes also emit config/approval/bypass semantics |
| `patch` replace | filesystem replace+truncate+write with task-CWD-resolved target; active config changes conservatively emit config/approval/bypass effects |
| `patch` V4A | add uses existence-aware whole-file semantics (create+write or replace+truncate+write); update emits replace+truncate+write; delete/move retain their specific effects; add under a missing parent also emits create-directory; move evaluates both endpoints; any active-config endpoint gets conservative control effects |
| `terminal` | opaque process authority; any semantic deny blocks, any semantic approval rule prompts, and protected-root policy requires fresh human approval or unattended deny |
| `execute_code` | opaque process authority; same conservative rules |
| `process_manage write/submit` | opaque process-stdin authority; same conservative rules |
| `process_manage close/kill/handoff` | effectful process control |
| `memory` mutations | memory change |
| `skill_manage` | skill change |
| `setup_mcp` | MCP configuration change |

These adapters are enumerated by `MIGRATED_TOOL_EFFECTS`. Unknown tools are not
claimed as migrated.

## Explicit remaining gaps

Phase 1 is not OS confinement and is not system-wide unification. In particular:

- native Codex app-server exec/patch approval remains a separate, snapshotted
  path;
- MCP and connector operations lack provider/resource mutability metadata;
- computer-use destructive actions and ACP edit approval remain separate;
- policy-control slash/TUI/dashboard mutations, cron-owned scripts, shell hooks,
  and direct plugin/internal subprocesses are not all routed through the model
  tool seams;
- subprocess descendants, aliases/functions/PATH substitution, scripts,
  downloaded code, and direct Python/Node/PowerShell filesystem APIs cannot be
  intercepted semantically without confinement or cooperation from the carrier;
- remote/container filesystem identities need namespace-aware target resolvers;
- path identity can still change between application-level authorization and an
  OS filesystem operation. Closing that TOCTOU class requires lower-level
  handle/open semantics or a confined filesystem broker;
- malicious arbitrary Python already running in the Hermes process can mutate
  runtime state or monkeypatch enforcement and is outside this cooperative
  boundary;
- browser/computer-use action semantics are not unified, and native Codex,
  generic MCP, and connector calls remain gaps unless separately constrained.

Accordingly, phase 1 should be reported as partial unless every effect-bearing
carrier relevant to a deployment is either migrated, disabled, or constrained
by a lower-level enforcement boundary.
