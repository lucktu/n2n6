# Windows Client Design

## Goal

Design a native Windows GUI client for this repository that manages `edge` connections through a visual interface aimed at operations and administrator users.

The client should:

- manage multiple saved connection profiles
- allow only one active connection at a time
- run `edge` in direct foreground-process mode rather than Windows service mode for the first version
- provide system tray control
- support diagnostics and real-time logs
- keep all client code, configuration, and related documentation isolated under `windows-client/`

## Scope

This design covers the Windows client product shape, runtime model, configuration model, UI structure, and implementation boundaries.

In scope:

- native Windows desktop client design
- profile management UX
- tray behavior
- diagnostics and logging UX
- versioned `edge.exe` discovery under `windows-client/bin/`
- single-file local configuration strategy
- module decomposition for implementation
- MVP feature boundary

Out of scope:

- implementing the client in this document
- managing `supernode` from the GUI
- Linux or cross-platform client support
- Windows service-first runtime mode
- multiple simultaneous active `edge` connections

## Directory Boundary

All Windows client code and documentation must remain isolated from the main repository code under a dedicated top-level directory:

```text
windows-client/
```

Nothing for the Windows GUI client should be mixed into the existing root-level `edge`, `supernode`, or generic repository docs unless explicitly needed later.

Recommended structure:

```text
windows-client/
  specs/
  plans/
  src/
  assets/
  bin/
  logs/
  exports/
  backups/
```

## Product Positioning

This client is an operations-oriented Windows control console for `n2n edge`, not a minimal consumer VPN toggle.

Primary characteristics:

- native Windows desktop application
- multiple saved profiles
- one active connection at a time
- strong visibility into runtime state
- integrated diagnostics and logs
- tray-based background presence
- portable deployment style

The target user is an operator or administrator who needs to manage, compare, and troubleshoot multiple `edge` configurations on Windows.

## Runtime Model

The first version uses direct foreground process control.

That means the GUI application itself launches and supervises the selected `edge.exe` as a child process, captures output, and presents state in the UI.

The first version does not treat Windows services as the primary runtime path.

## Profile Model

The client supports multiple saved profiles, but only one can be active at any given time.

Each profile contains:

- profile identity and display metadata
- the chosen `edge` version
- connection parameters
- network interface parameters
- encryption settings
- advanced options

Each profile binds to exactly one `edge` version identifier.

## Single Active Connection Rule

The client must enforce this product rule globally:

- multiple profiles may exist
- only one profile may be active
- connecting a new profile requires explicit replacement of the current active connection

The internal runtime state should distinguish:

- `selectedProfileId`: currently selected in the UI
- `activeProfileId`: currently running
- `pendingProfileId`: preparing to connect

This prevents UI ambiguity during profile switching and reconnect flows.

## UI Information Architecture

The main product areas are:

1. Profile Center
2. Connection Console
3. Real-Time Log Workspace
4. Diagnostics Center
5. Tray Entry Point

### 1. Profile Center

Responsibilities:

- list saved profiles
- create profile
- edit profile
- copy profile
- delete profile
- import profile data
- export profile data

The main UI entry pattern is list-based, while create/edit flows use a wizard.

### 2. Connection Console

Responsibilities:

- display selected profile summary
- show current runtime state
- connect
- disconnect
- reconnect
- display active process details

Recommended runtime fields shown in the console:

- active profile name
- selected `edge` version
- resolved binary path
- PID
- start time
- uptime
- supernode address
- TAP device name
- IPv4 / IPv6 values

### 3. Real-Time Log Workspace

Responsibilities:

- capture stdout/stderr from `edge.exe`
- show real-time logs
- filter by severity or category
- search log text
- export logs
- highlight failures

The log area should preserve raw output order while also enabling extraction of structured error summaries.

### 4. Diagnostics Center

Responsibilities:

- preflight validation before connection
- full diagnostics on demand
- targeted diagnostics after failures

The diagnostics view should show structured results with:

- title
- status: pass / warning / fail
- reason
- suggestion

### 5. Tray Entry Point

Responsibilities:

- keep the application resident in the background
- expose quick connection control
- restore the main window
- exit the app

Tray right-click menu must contain only:

- current status
- current active profile name
- connect current selected profile
- disconnect current connection
- open main window
- exit

It must not include:

- recent profile list
- recent error entry

## Main Window Layout

Recommended layout:

- left panel: profile list
- top right: connection control card
- bottom right: tabbed workspace

Tabbed workspace should include:

- Logs
- Diagnostics
- Profile Details

Recommended behavior:

- default open tab is Logs
- double-clicking a profile attempts connection
- right-clicking a profile opens operations menu
- closing the main window minimizes to tray instead of quitting

## Profile Editing Flow

Profile editing should use a guided wizard rather than a single dense form.

Recommended steps:

1. Basic Connection
2. Network Interface
3. Security And Advanced Options
4. Review And Preflight

### Step 1: Basic Connection

Fields:

- profile name
- `edge` version selector
- supernode host
- supernode port
- community
- resolution mode: auto / IPv4 / IPv6

### Step 2: Network Interface

Fields:

- TAP adapter selector
- IPv4 mode and address string
- IPv6 address string
- MAC address

### Step 3: Security And Advanced Options

Fields:

- encryption mode
- plaintext key
- multicast option
- routing/forwarding options
- management port
- extra args

### Step 4: Review And Preflight

Fields or outputs:

- final command preview
- selected `edge` version and path
- warning that key is stored in plaintext
- preflight validation results

## Portable Storage Strategy

The Windows client must behave like a portable application.

All files must live under `windows-client/` and should not rely on:

- `%AppData%`
- user profile folders
- registry-backed profile storage

## Configuration Storage

The approved storage model is a single total configuration file in the Windows client directory.

The configuration file contains:

- all profiles
- app UI state

Recommended logical structure:

- `profiles`
- `appState`

Even though it is one file, those two sections should remain distinct in the schema.

## Secret Storage Policy

Encryption keys are allowed to be stored in plaintext in the local configuration file.

This is intentional for portable ops/admin workflows.

Even so, the UI must still reduce accidental disclosure by:

- warning once on save that keys are stored in plaintext
- showing masked values in command preview by default
- masking keys in exported logs and diagnostic summaries by default

## Versioned Binary Discovery

This is a core product requirement.

The client must not hardcode a single `edge.exe`.

Instead, it discovers binaries from:

```text
windows-client/bin/<version>/edge.exe
```

Examples:

- `windows-client/bin/v2/edge.exe`
- `windows-client/bin/v26/edge.exe`
- `windows-client/bin/v3/edge.exe`

Each profile stores a version identifier such as `v2`, `v26`, or `v3`.

At runtime, the client resolves the actual executable path by combining:

- application root
- `bin/`
- version id
- `edge.exe`

The config should store the version identifier, not an absolute executable path.

## Version Discovery Model

At startup, and on explicit refresh, the client scans:

```text
windows-client/bin/*/edge.exe
```

Each discovered version entry should contain:

- `id`
- `displayName`
- `relativePath`
- `detectedVersionText`
- `isValid`
- `lastScanError`

If available, version text can be derived from executable output or a simple probe command.

The display name can default to the directory name.

## Version-Aware Validation

Connection preflight must validate version selection before process start.

Checks should include:

1. profile has a selected version id
2. `bin/<version>/edge.exe` exists
3. the executable is launchable
4. version probing is acceptable or at least not fatally broken

The first version of the client should not attempt a complex compatibility matrix across all possible `edge` versions. It should focus on executable existence, launchability, and basic probe success.

## Runtime State Machine

Recommended runtime states:

- `idle`
- `validating`
- `starting`
- `running`
- `stopping`
- `restarting`
- `error`

Expected transitions:

- `idle -> validating -> starting -> running`
- `running -> stopping -> idle`
- `running -> restarting -> starting -> running`
- any critical failure -> `error`
- `error -> validating`
- `error -> idle`

UI actions must respect these states. For example, connect should be disabled during `starting` and `stopping`.

## Process Supervision

Because the app runs `edge.exe` directly in foreground mode, the GUI acts as a small supervisor.

The connection controller should track:

- process handle
- process id
- start timestamp
- active profile id
- resolved executable path
- resolved version id
- resolved version text
- generated argv
- exit code
- last failure reason

Start flow:

1. resolve selected version path
2. build argv from profile
3. run quick preflight
4. if another profile is active, require explicit replacement
5. launch the selected `edge.exe`
6. attach log capture
7. enter `starting`
8. transition to `running` when stable

Stop flow:

1. enter `stopping`
2. attempt graceful stop
3. wait short timeout
4. force terminate if required
5. release process resources
6. transition to `idle`

## Command Builder

The client should not store raw command strings as the primary profile model.

Instead:

- profiles are stored as structured fields
- a dedicated command builder generates argv at runtime
- the same command builder also generates a command preview for the UI

This keeps validation, preview, and execution consistent.

The preview should identify:

- selected binary version
- resolved executable path
- final arguments
- masked secret values by default

## Diagnostics Model

Diagnostics are split into two levels.

### Quick Preflight

Runs automatically on connect.

Focus:

- selected version exists
- executable exists and is runnable
- required fields are present
- TAP environment is acceptable
- supernode value format is valid

### Full Diagnostics

Runs on demand or after failure.

Focus:

- executable and version validation
- configuration completeness
- TAP presence and matching
- local port conflicts
- DNS resolution
- basic remote reachability checks

## Error Classification

Recommended error categories:

1. Configuration Error
2. Environment Error
3. Startup Failure
4. Runtime Interruption
5. Binary Version Error

### Binary Version Error

Examples:

- configured version does not exist
- version directory exists but `edge.exe` is missing
- executable cannot be launched
- version probe fails in a fatal way

This category should be surfaced clearly because version selection is now a first-class product concept.

## Logging Model

Use two logical layers:

1. Raw Output Stream
2. Structured Runtime Events

Raw output preserves exact process text.

Structured events allow the UI to show high-value summaries such as:

- connection started
- binary version selected
- config parse failure
- TAP open failure
- supernode resolve failure
- runtime termination

## Main UI Data Visibility Rules

The selected version and resolved binary path must be visible in all relevant places:

- profile list summary
- connection control card
- profile details tab
- command preview
- diagnostics results when version-related failures occur

This avoids confusion when operators compare behavior across `v2`, `v26`, and `v3` binaries.

## Failure Handling For Portable Single-File Storage

Because all profiles live in one configuration file, the design must include safeguards:

1. automatic backup before write
2. atomic file replacement when saving
3. recovery flow when config file is corrupted

The app should never crash simply because the single config file is malformed.

## Recommended Windows Client Directory Layout

The product should assume a directory layout like this:

```text
windows-client/
  src/
  specs/
  plans/
  assets/
  bin/
    v2/
      edge.exe
    v26/
      edge.exe
    v3/
      edge.exe
  logs/
  exports/
  backups/
  client-config.json
```

Implementation may expand this layout, but the core principles must stay intact:

- Windows client stays isolated under `windows-client/`
- versioned binaries live under `windows-client/bin/`
- profiles live in one config file in `windows-client/`

## Technology Recommendation

Recommended first implementation stack:

- C#
- WPF

Reasoning:

- good Windows desktop fit
- mature tray support
- practical process supervision support
- suitable for wizard-based forms, logs, and diagnostics

Alternative stacks such as Qt are possible, but not the primary recommendation for the first implementation.

## Codebase Decomposition

Recommended implementation modules under `windows-client/src/`:

1. App Shell
2. Profile Module
3. Version Discovery Module
4. Command Builder
5. Connection Controller
6. Log Module
7. Diagnostics Module
8. UI Pages / Views

## MVP Scope

The first deliverable should include:

- multiple profiles in one config file
- version discovery from `windows-client/bin/`
- per-profile version selection
- single active connection enforcement
- connect / disconnect / reconnect
- tray control
- real-time logs
- quick preflight diagnostics
- full diagnostics view
- command preview
- backup and atomic save strategy for config writes

The first deliverable should exclude:

- service-first control model
- multi-connection concurrency
- supernode control console
- advanced routing editor
- complex binary compatibility matrix

## Implementation Order

Recommended build order:

1. app shell and tray
2. single-file config store
3. version discovery from `windows-client/bin/`
4. profile list and profile wizard
5. command builder
6. connection controller and process supervision
7. log capture UI
8. diagnostics UI and result engine
9. config backup and recovery hardening

## Final Design Summary

This Windows client is designed as a native, portable, operations-oriented control console for versioned `edge` binaries.

Its defining constraints are:

- everything lives under `windows-client/`
- profiles live in one local config file
- keys may be stored in plaintext
- binaries are discovered under `windows-client/bin/<version>/edge.exe`
- one active connection at a time
- operators get logs, diagnostics, tray control, and explicit version visibility

These constraints are internally consistent and focused enough for a single implementation plan and an MVP-first build.
