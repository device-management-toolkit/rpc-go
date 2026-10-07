# Known enhancement directions

These are candidate enhancements, each with the constraints that apply to it. Anything marked **design change** needs a new decision in `mcp/docs/ARCHITECTURE.md` and user sign-off before you implement it (SKILL.md, workflow C).

## Fits the current design (workflow A or B)

| Enhancement | rpc side | MCP side | Notes |
|---|---|---|---|
| Boot options / one-time boot (PXE, HDD, IDE-R) | New `rpc boot` command using go-wsman-messages `amt/boot` and `cim/boot` | Read-only `get_boot_options`; destructive `set_next_boot` behind the confirm gate | Usually combined with `power_action reset`; document the two-step flow in the tool description |
| CIRA / remote access status | Already in `amtinfo --ras` | Covered by `get_device_info` `fields: ["remoteAccess"]` | Prefer documenting the existing field over adding a tool |
| AMT event and audit logs | `diagnostics wsman get --class AMT_AuditLog` / `AMT_EventLogEntry` exist | Use `wsman_get`, or a dedicated tool with a friendlier output | A dedicated tool needs an rpc command that has a stable JSON shape |
| Configure actions (sync clock, sync hostname, TLS, CIRA) | Existing `rpc configure <sub>` | Destructive or state-changing tools with confirm gate | Check that each subcommand's `--json` output is an object; several print logs only, so add `--json` output in a separate rpc PR first |
| Activation / deactivation | Existing `rpc activate`, `rpc deactivate --json` | Highly destructive tools behind a dedicated `cfg.AllowProvisioning` flag, off by default | Profiles, URLs and certificates must come from server config, never tool input (D6) |
| MCP resources (e.g. `rpc://device/info`) | none | `server.AddResource` reading `amtinfo --json` | Still one rpc run per read (D5) |

## Design changes (need a new decision)

| Enhancement | Why it is a design change | Direction |
|---|---|---|
| Fleet or out-of-band power (power **on**, act on other devices) | Breaks D1 (local-only) | A separate Console/MPS-backed MCP server or tool set calling the MPS power API by GUID. Devices are already registered through `register_device` |
| Auth on HTTP mode or non-loopback binding | Changes D6 | Bearer token from a server-side secret, plus TLS; still deny by default |
| Long-running rpc or a library-mode backend | Breaks D2 and rpc-go's one-shot lifecycle (`AfterApply` once, MEI handle closed) | Keep subprocess isolation unless profiling proves process start is a bottleneck |
| Moving `mcp/` to its own repo | D3 already allows it | No code changes; move the docs and the CI job, and pin the minimum rpc version that has the required commands |
| Using `--lmsaddress` to reach remote AMT | rpc-go hardcodes `127.0.0.1`; changes rpc-go architecture (D4) | Prefer the Console/MPS route above |

## Fixes in rpc-go worth proposing separately

- `cmd/rpc/main.go handleErrorAndExit` uses a type assertion, so Kong-wrapped `CustomError`s exit with 10. Using `errors.As` would give rpc-mcp exact exit codes, and the `Error <N>:` parsing in `runner.go` could then be removed. This is a separate `fix(cli)` PR.
- `writePowerOutput` in `power.go` is generic. If a second command needs it, move it to a shared output helper in `internal/commands` as a `refactor:` PR.
