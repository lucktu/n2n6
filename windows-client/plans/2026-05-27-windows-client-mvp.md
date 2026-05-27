# Windows Client MVP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first working MVP of the Windows GUI client under `windows-client/` that manages versioned `edge.exe` binaries, multiple saved profiles, one active connection, tray control, logs, and diagnostics.

**Architecture:** Implement a WPF desktop app that stays fully isolated under `windows-client/`, stores all state in a single local config file, discovers binaries from `windows-client/bin/<version>/edge.exe`, and supervises one foreground `edge.exe` process through a dedicated connection controller. Keep runtime logic out of the UI by separating profile storage, version discovery, command building, diagnostics, logging, and process supervision into focused services.

**Tech Stack:** C#, .NET, WPF, xUnit or NUnit for tests, JSON config storage, Windows process APIs, system tray APIs

---

## File Structure

- Create: `windows-client/src/WindowsClient.sln`
  Responsibility: Visual Studio / .NET solution root for all client projects.
- Create: `windows-client/src/WindowsClient.App/WindowsClient.App.csproj`
  Responsibility: WPF application project.
- Create: `windows-client/src/WindowsClient.Core/WindowsClient.Core.csproj`
  Responsibility: domain models, interfaces, validation, command building, diagnostics contracts.
- Create: `windows-client/src/WindowsClient.Infrastructure/WindowsClient.Infrastructure.csproj`
  Responsibility: file storage, version discovery, process control, logging adapters.
- Create: `windows-client/src/WindowsClient.App/App.xaml`
  Responsibility: application bootstrap.
- Create: `windows-client/src/WindowsClient.App/App.xaml.cs`
  Responsibility: startup, single-instance enforcement, tray lifetime, dependency wiring.
- Create: `windows-client/src/WindowsClient.App/MainWindow.xaml`
  Responsibility: main shell UI with profile list, control card, and tab workspace.
- Create: `windows-client/src/WindowsClient.App/MainWindow.xaml.cs`
  Responsibility: main window behavior only.
- Create: `windows-client/src/WindowsClient.App/ViewModels/MainWindowViewModel.cs`
  Responsibility: shell-level state and commands.
- Create: `windows-client/src/WindowsClient.App/ViewModels/ProfileWizardViewModel.cs`
  Responsibility: profile create/edit wizard state.
- Create: `windows-client/src/WindowsClient.App/Views/ProfileWizardWindow.xaml`
  Responsibility: wizard UI.
- Create: `windows-client/src/WindowsClient.App/Views/ProfileWizardWindow.xaml.cs`
  Responsibility: wizard window behavior only.
- Create: `windows-client/src/WindowsClient.Core/Models/ProfileModel.cs`
  Responsibility: structured profile definition.
- Create: `windows-client/src/WindowsClient.Core/Models/AppStateModel.cs`
  Responsibility: persisted UI state.
- Create: `windows-client/src/WindowsClient.Core/Models/ClientConfigModel.cs`
  Responsibility: root config file model containing `profiles` and `appState`.
- Create: `windows-client/src/WindowsClient.Core/Models/VersionInfoModel.cs`
  Responsibility: discovered `edge` version metadata.
- Create: `windows-client/src/WindowsClient.Core/Models/ConnectionRuntimeState.cs`
  Responsibility: runtime connection state record.
- Create: `windows-client/src/WindowsClient.Core/Models/DiagnosticResult.cs`
  Responsibility: structured diagnostics result.
- Create: `windows-client/src/WindowsClient.Core/Models/LogEntry.cs`
  Responsibility: UI log record.
- Create: `windows-client/src/WindowsClient.Core/Interfaces/IProfileStore.cs`
  Responsibility: config load/save abstraction.
- Create: `windows-client/src/WindowsClient.Core/Interfaces/IVersionDiscoveryService.cs`
  Responsibility: version scanning abstraction.
- Create: `windows-client/src/WindowsClient.Core/Interfaces/ICommandBuilder.cs`
  Responsibility: argv and preview generation abstraction.
- Create: `windows-client/src/WindowsClient.Core/Interfaces/IConnectionController.cs`
  Responsibility: single active connection orchestration abstraction.
- Create: `windows-client/src/WindowsClient.Core/Interfaces/IDiagnosticsService.cs`
  Responsibility: quick and full diagnostics abstraction.
- Create: `windows-client/src/WindowsClient.Core/Interfaces/ILogBuffer.cs`
  Responsibility: runtime log collection abstraction.
- Create: `windows-client/src/WindowsClient.Core/Services/ProfileValidator.cs`
  Responsibility: profile field validation rules.
- Create: `windows-client/src/WindowsClient.Core/Services/CommandPreviewMasker.cs`
  Responsibility: hide plaintext secrets in previews and exports.
- Create: `windows-client/src/WindowsClient.Infrastructure/Storage/JsonProfileStore.cs`
  Responsibility: single-file config load/save, backup, atomic write.
- Create: `windows-client/src/WindowsClient.Infrastructure/Versions/VersionDiscoveryService.cs`
  Responsibility: scan `windows-client/bin/*/edge.exe` and probe binaries.
- Create: `windows-client/src/WindowsClient.Infrastructure/Processes/ConnectionController.cs`
  Responsibility: launch, stop, reconnect, and supervise one `edge.exe` process.
- Create: `windows-client/src/WindowsClient.Infrastructure/Processes/EdgeProcessProbe.cs`
  Responsibility: version and launchability probe for `edge.exe`.
- Create: `windows-client/src/WindowsClient.Infrastructure/Logging/InMemoryLogBuffer.cs`
  Responsibility: collect stdout/stderr for UI and exports.
- Create: `windows-client/src/WindowsClient.Infrastructure/Diagnostics/DiagnosticsService.cs`
  Responsibility: quick and full diagnostics implementation.
- Create: `windows-client/src/WindowsClient.Tests/WindowsClient.Tests.csproj`
  Responsibility: automated tests for config, version discovery, command building, validation, and state transitions.
- Create: `windows-client/src/WindowsClient.Tests/ProfileStoreTests.cs`
  Responsibility: tests for single-file config persistence and backup behavior.
- Create: `windows-client/src/WindowsClient.Tests/VersionDiscoveryTests.cs`
  Responsibility: tests for `bin/<version>/edge.exe` scanning.
- Create: `windows-client/src/WindowsClient.Tests/CommandBuilderTests.cs`
  Responsibility: tests for argv generation and secret masking.
- Create: `windows-client/src/WindowsClient.Tests/ProfileValidatorTests.cs`
  Responsibility: tests for wizard and save validation rules.
- Create: `windows-client/src/WindowsClient.Tests/ConnectionControllerTests.cs`
  Responsibility: tests for single active connection behavior.
- Create: `windows-client/client-config.json`
  Responsibility: runtime config file produced by the app; do not hand-author in implementation steps except for minimal sample/test fixtures.
- Create: `windows-client/bin/`
  Responsibility: user-managed versioned `edge.exe` directories.

### Task 1: Scaffold the solution and the isolated Windows client layout

**Files:**
- Create: `windows-client/src/WindowsClient.sln`
- Create: `windows-client/src/WindowsClient.App/WindowsClient.App.csproj`
- Create: `windows-client/src/WindowsClient.Core/WindowsClient.Core.csproj`
- Create: `windows-client/src/WindowsClient.Infrastructure/WindowsClient.Infrastructure.csproj`
- Create: `windows-client/src/WindowsClient.Tests/WindowsClient.Tests.csproj`

- [ ] **Step 1: Verify the target parent directory exists**

Run:

```powershell
Test-Path -LiteralPath "windows-client"
```

Expected:

```text
False or True, but the command succeeds and confirms whether the top-level client directory already exists.
```

- [ ] **Step 2: Create the Windows client root directories**

Run:

```powershell
New-Item -ItemType Directory -Path "windows-client","windows-client\src","windows-client\specs","windows-client\plans","windows-client\assets","windows-client\bin","windows-client\logs","windows-client\exports","windows-client\backups" -Force
```

Expected:

```text
Directory creation output for the Windows client subtree.
```

- [ ] **Step 3: Create the .NET solution and projects**

Run:

```powershell
dotnet new sln -n WindowsClient --output "windows-client\src"; dotnet new wpf -n WindowsClient.App --output "windows-client\src\WindowsClient.App"; dotnet new classlib -n WindowsClient.Core --output "windows-client\src\WindowsClient.Core"; dotnet new classlib -n WindowsClient.Infrastructure --output "windows-client\src\WindowsClient.Infrastructure"; dotnet new xunit -n WindowsClient.Tests --output "windows-client\src\WindowsClient.Tests"
```

Expected:

```text
The solution and four projects are created successfully.
```

- [ ] **Step 4: Add the projects to the solution and reference graph**

Run:

```powershell
dotnet sln "windows-client\src\WindowsClient.sln" add "windows-client\src\WindowsClient.App\WindowsClient.App.csproj" "windows-client\src\WindowsClient.Core\WindowsClient.Core.csproj" "windows-client\src\WindowsClient.Infrastructure\WindowsClient.Infrastructure.csproj" "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj"; dotnet add "windows-client\src\WindowsClient.App\WindowsClient.App.csproj" reference "windows-client\src\WindowsClient.Core\WindowsClient.Core.csproj" "windows-client\src\WindowsClient.Infrastructure\WindowsClient.Infrastructure.csproj"; dotnet add "windows-client\src\WindowsClient.Infrastructure\WindowsClient.Infrastructure.csproj" reference "windows-client\src\WindowsClient.Core\WindowsClient.Core.csproj"; dotnet add "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj" reference "windows-client\src\WindowsClient.Core\WindowsClient.Core.csproj" "windows-client\src\WindowsClient.Infrastructure\WindowsClient.Infrastructure.csproj"
```

Expected:

```text
Projects are added to the solution, and project references are added successfully.
```

- [ ] **Step 5: Run the baseline test suite**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.sln"
```

Expected:

```text
The default scaffold tests pass, proving the isolated client solution is healthy before feature work.
```

- [ ] **Step 6: Commit the scaffold**

Run:

```powershell
git add windows-client && git commit -m "feat: scaffold windows client solution"
```

Expected:

```text
A commit containing only the isolated Windows client skeleton.
```

### Task 2: Define the core models, config schema, and validation rules

**Files:**
- Create: `windows-client/src/WindowsClient.Core/Models/ProfileModel.cs`
- Create: `windows-client/src/WindowsClient.Core/Models/AppStateModel.cs`
- Create: `windows-client/src/WindowsClient.Core/Models/ClientConfigModel.cs`
- Create: `windows-client/src/WindowsClient.Core/Models/VersionInfoModel.cs`
- Create: `windows-client/src/WindowsClient.Core/Models/ConnectionRuntimeState.cs`
- Create: `windows-client/src/WindowsClient.Core/Models/DiagnosticResult.cs`
- Create: `windows-client/src/WindowsClient.Core/Models/LogEntry.cs`
- Create: `windows-client/src/WindowsClient.Core/Services/ProfileValidator.cs`
- Create: `windows-client/src/WindowsClient.Tests/ProfileValidatorTests.cs`

- [ ] **Step 1: Write failing validation tests for required profile rules**

Create `windows-client/src/WindowsClient.Tests/ProfileValidatorTests.cs` with tests that cover:

```csharp
using WindowsClient.Core.Models;
using WindowsClient.Core.Services;

namespace WindowsClient.Tests;

public sealed class ProfileValidatorTests
{
    [Fact]
    public void Validate_ShouldFail_WhenNameIsMissing()
    {
        var validator = new ProfileValidator();
        var profile = new ProfileModel { Name = "", EdgeVersionId = "v26", SupernodeHost = "vpn.example.com", SupernodePort = 1234, Community = "ops" };

        var result = validator.Validate(profile, existingNames: Array.Empty<string>());

        Assert.Contains(result.Errors, error => error.Code == "Profile.Name.Required");
    }

    [Fact]
    public void Validate_ShouldFail_WhenVersionIsMissing()
    {
        var validator = new ProfileValidator();
        var profile = new ProfileModel { Name = "Office", EdgeVersionId = "", SupernodeHost = "vpn.example.com", SupernodePort = 1234, Community = "ops" };

        var result = validator.Validate(profile, existingNames: Array.Empty<string>());

        Assert.Contains(result.Errors, error => error.Code == "Profile.EdgeVersion.Required");
    }

    [Fact]
    public void Validate_ShouldFail_WhenNameDuplicatesAnotherProfile()
    {
        var validator = new ProfileValidator();
        var profile = new ProfileModel { Name = "Office", EdgeVersionId = "v26", SupernodeHost = "vpn.example.com", SupernodePort = 1234, Community = "ops" };

        var result = validator.Validate(profile, existingNames: new[] { "Office" });

        Assert.Contains(result.Errors, error => error.Code == "Profile.Name.Duplicate");
    }
}
```

- [ ] **Step 2: Run the validation tests to confirm failure**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj" --filter ProfileValidatorTests
```

Expected:

```text
FAIL because the core models and validator are not implemented yet.
```

- [ ] **Step 3: Implement the core models and validator minimally**

Create the models and validator with fields that match the approved spec, including:

```csharp
namespace WindowsClient.Core.Models;

public sealed class ProfileModel
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string EdgeVersionId { get; set; } = string.Empty;
    public string SupernodeHost { get; set; } = string.Empty;
    public int SupernodePort { get; set; }
    public string Community { get; set; } = string.Empty;
    public string ResolutionMode { get; set; } = "auto";
    public string TapName { get; set; } = string.Empty;
    public string IPv4AddressWithPrefix { get; set; } = string.Empty;
    public string IPv6AddressWithPrefix { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public string EncryptionMode { get; set; } = string.Empty;
    public string PlaintextKey { get; set; } = string.Empty;
    public bool AcceptMulticast { get; set; }
    public bool EnableRouting { get; set; }
    public int? ManagementPort { get; set; }
    public string ExtraArgs { get; set; } = string.Empty;
    public DateTimeOffset? LastUsedAt { get; set; }
}
```

And a validator that returns named errors for required name, required version, duplicate name, required supernode, valid port range, and required community.

- [ ] **Step 4: Run the validation tests to confirm pass**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj" --filter ProfileValidatorTests
```

Expected:

```text
PASS for the validator test set.
```

- [ ] **Step 5: Commit the model and validation layer**

Run:

```powershell
git add windows-client && git commit -m "feat: add windows client core models"
```

Expected:

```text
A commit with the core schema and validation rules.
```

### Task 3: Implement single-file config storage with backup and atomic save

**Files:**
- Create: `windows-client/src/WindowsClient.Core/Interfaces/IProfileStore.cs`
- Create: `windows-client/src/WindowsClient.Infrastructure/Storage/JsonProfileStore.cs`
- Create: `windows-client/src/WindowsClient.Tests/ProfileStoreTests.cs`

- [ ] **Step 1: Write failing tests for save, backup, and reload behavior**

Create `windows-client/src/WindowsClient.Tests/ProfileStoreTests.cs` with tests that verify:

```csharp
using WindowsClient.Core.Models;
using WindowsClient.Infrastructure.Storage;

namespace WindowsClient.Tests;

public sealed class ProfileStoreTests
{
    [Fact]
    public async Task SaveAsync_ShouldCreateSingleConfigFile()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var store = new JsonProfileStore(root);
        var config = new ClientConfigModel();
        config.Profiles.Add(new ProfileModel { Name = "Office", EdgeVersionId = "v26", SupernodeHost = "vpn.example.com", SupernodePort = 1234, Community = "ops" });

        await store.SaveAsync(config, CancellationToken.None);

        Assert.True(File.Exists(Path.Combine(root, "client-config.json")));
    }

    [Fact]
    public async Task SaveAsync_ShouldCreateBackupWhenOverwriting()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var store = new JsonProfileStore(root);
        var config = new ClientConfigModel();
        config.Profiles.Add(new ProfileModel { Name = "Office", EdgeVersionId = "v26", SupernodeHost = "vpn.example.com", SupernodePort = 1234, Community = "ops" });

        await store.SaveAsync(config, CancellationToken.None);
        await store.SaveAsync(config, CancellationToken.None);

        Assert.True(Directory.Exists(Path.Combine(root, "backups")));
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(root, "backups")));
    }
}
```

- [ ] **Step 2: Run the store tests to verify failure**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj" --filter ProfileStoreTests
```

Expected:

```text
FAIL because the store interface and implementation do not exist yet.
```

- [ ] **Step 3: Implement `IProfileStore` and `JsonProfileStore`**

Implement a store that:

- uses `windows-client/client-config.json`
- writes to a temp file first
- atomically replaces the live config file
- writes backup copies into `windows-client/backups/`
- loads missing config as a default empty `ClientConfigModel`

Use clear methods such as:

```csharp
Task<ClientConfigModel> LoadAsync(CancellationToken cancellationToken);
Task SaveAsync(ClientConfigModel config, CancellationToken cancellationToken);
```

- [ ] **Step 4: Run the store tests to verify pass**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj" --filter ProfileStoreTests
```

Expected:

```text
PASS for config creation, overwrite backup, and reload behavior.
```

- [ ] **Step 5: Commit the storage layer**

Run:

```powershell
git add windows-client && git commit -m "feat: add windows client profile store"
```

Expected:

```text
A commit with single-file config persistence, backup, and atomic save behavior.
```

### Task 4: Implement version discovery from `windows-client/bin/`

**Files:**
- Create: `windows-client/src/WindowsClient.Core/Interfaces/IVersionDiscoveryService.cs`
- Create: `windows-client/src/WindowsClient.Infrastructure/Versions/VersionDiscoveryService.cs`
- Create: `windows-client/src/WindowsClient.Infrastructure/Processes/EdgeProcessProbe.cs`
- Create: `windows-client/src/WindowsClient.Tests/VersionDiscoveryTests.cs`

- [ ] **Step 1: Write failing tests for version scanning**

Create `windows-client/src/WindowsClient.Tests/VersionDiscoveryTests.cs` with tests that verify:

```csharp
using WindowsClient.Infrastructure.Versions;

namespace WindowsClient.Tests;

public sealed class VersionDiscoveryTests
{
    [Fact]
    public async Task DiscoverAsync_ShouldReturnVersionFoldersContainingEdgeExe()
    {
        var root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "bin", "v26"));
        await File.WriteAllTextAsync(Path.Combine(root, "bin", "v26", "edge.exe"), "fake-binary");

        var service = new VersionDiscoveryService(root, probe: null);

        var versions = await service.DiscoverAsync(CancellationToken.None);

        Assert.Contains(versions, version => version.Id == "v26");
    }
}
```

- [ ] **Step 2: Run the version discovery tests to confirm failure**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj" --filter VersionDiscoveryTests
```

Expected:

```text
FAIL because version discovery and probe logic are not implemented yet.
```

- [ ] **Step 3: Implement version discovery and probe contracts**

Implement a service that scans:

```text
<root>\bin\*\edge.exe
```

and returns `VersionInfoModel` entries with:

- directory name as `Id`
- relative path under `bin`
- `IsValid` based on file existence and basic probe result
- `DetectedVersionText` when available

If real probing is too environment-dependent for unit tests, keep the probe behind a small abstraction and let tests pass a null or fake probe.

- [ ] **Step 4: Run the version discovery tests to confirm pass**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj" --filter VersionDiscoveryTests
```

Expected:

```text
PASS for version folder scanning and metadata projection.
```

- [ ] **Step 5: Commit version discovery**

Run:

```powershell
git add windows-client && git commit -m "feat: add windows client version discovery"
```

Expected:

```text
A commit with `bin/<version>/edge.exe` discovery support.
```

### Task 5: Implement command building and preview masking

**Files:**
- Create: `windows-client/src/WindowsClient.Core/Interfaces/ICommandBuilder.cs`
- Create: `windows-client/src/WindowsClient.Core/Services/CommandPreviewMasker.cs`
- Create: `windows-client/src/WindowsClient.Infrastructure/Processes/CommandBuilder.cs`
- Create: `windows-client/src/WindowsClient.Tests/CommandBuilderTests.cs`

- [ ] **Step 1: Write failing tests for argv generation and secret masking**

Create `windows-client/src/WindowsClient.Tests/CommandBuilderTests.cs` with tests that verify:

```csharp
using WindowsClient.Core.Models;
using WindowsClient.Infrastructure.Processes;

namespace WindowsClient.Tests;

public sealed class CommandBuilderTests
{
    [Fact]
    public void Build_ShouldIncludeSelectedVersionInputsInGeneratedArguments()
    {
        var builder = new CommandBuilder();
        var profile = new ProfileModel
        {
            Name = "Office",
            EdgeVersionId = "v26",
            SupernodeHost = "vpn.example.com",
            SupernodePort = 1234,
            Community = "ops",
            TapName = "tap-ops",
            IPv4AddressWithPrefix = "static:192.168.10.5/24",
            PlaintextKey = "secret"
        };

        var command = builder.Build(profile, resolvedEdgePath: "bin\\v26\\edge.exe");

        Assert.Contains("-c", command.Arguments);
        Assert.Contains("ops", command.Arguments);
        Assert.Contains("-l", command.Arguments);
        Assert.Contains("vpn.example.com:1234", command.Arguments);
    }

    [Fact]
    public void Build_ShouldMaskPlaintextKeyInPreview()
    {
        var builder = new CommandBuilder();
        var profile = new ProfileModel
        {
            Name = "Office",
            EdgeVersionId = "v26",
            SupernodeHost = "vpn.example.com",
            SupernodePort = 1234,
            Community = "ops",
            PlaintextKey = "secret"
        };

        var command = builder.Build(profile, resolvedEdgePath: "bin\\v26\\edge.exe");

        Assert.DoesNotContain("secret", command.MaskedPreview);
        Assert.Contains("***", command.MaskedPreview);
    }
}
```

- [ ] **Step 2: Run the command builder tests to confirm failure**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj" --filter CommandBuilderTests
```

Expected:

```text
FAIL because the command builder is not implemented yet.
```

- [ ] **Step 3: Implement the command builder**

Implement a result model and builder that produce:

- resolved executable path
- argument list
- unmasked preview for internal execution if needed
- masked preview for UI display

Keep the implementation minimal and aligned with the approved MVP fields: version, community, supernode, tap name, IPv4, IPv6, MAC, encryption key, multicast, routing, management port, extra args.

- [ ] **Step 4: Run the command builder tests to confirm pass**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj" --filter CommandBuilderTests
```

Expected:

```text
PASS for argv generation and masked preview behavior.
```

- [ ] **Step 5: Commit command building**

Run:

```powershell
git add windows-client && git commit -m "feat: add windows client command builder"
```

Expected:

```text
A commit with command generation and preview masking.
```

### Task 6: Implement connection control and one-active-connection state handling

**Files:**
- Create: `windows-client/src/WindowsClient.Core/Interfaces/IConnectionController.cs`
- Create: `windows-client/src/WindowsClient.Infrastructure/Processes/ConnectionController.cs`
- Create: `windows-client/src/WindowsClient.Infrastructure/Logging/InMemoryLogBuffer.cs`
- Create: `windows-client/src/WindowsClient.Core/Interfaces/ILogBuffer.cs`
- Create: `windows-client/src/WindowsClient.Tests/ConnectionControllerTests.cs`

- [ ] **Step 1: Write failing tests for single active connection behavior**

Create `windows-client/src/WindowsClient.Tests/ConnectionControllerTests.cs` with tests that verify:

```csharp
using WindowsClient.Core.Models;
using WindowsClient.Infrastructure.Processes;

namespace WindowsClient.Tests;

public sealed class ConnectionControllerTests
{
    [Fact]
    public async Task StartAsync_ShouldRejectSecondActiveProfileWithoutReplacement()
    {
        var controller = new ConnectionController(/* fakes */);
        var first = new ProfileModel { Name = "Office", EdgeVersionId = "v26", SupernodeHost = "vpn.example.com", SupernodePort = 1234, Community = "ops" };
        var second = new ProfileModel { Name = "Lab", EdgeVersionId = "v3", SupernodeHost = "lab.example.com", SupernodePort = 1234, Community = "lab" };

        await controller.MarkRunningForTestAsync(first);

        await Assert.ThrowsAsync<InvalidOperationException>(() => controller.StartAsync(second, replaceActive: false, CancellationToken.None));
    }
}
```

- [ ] **Step 2: Run the controller tests to verify failure**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj" --filter ConnectionControllerTests
```

Expected:

```text
FAIL because the controller and runtime state behavior do not exist yet.
```

- [ ] **Step 3: Implement minimal connection controller logic**

Implement a controller that:

- tracks `selected`, `active`, and `pending` profile state
- enforces one active connection at a time
- exposes `StartAsync`, `StopAsync`, and `RestartAsync`
- records runtime state transitions: `idle`, `validating`, `starting`, `running`, `stopping`, `restarting`, `error`

For the first pass, keep real process launch thin and testable behind small abstractions rather than embedding raw `Process` code directly in the state logic.

- [ ] **Step 4: Run the controller tests to verify pass**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj" --filter ConnectionControllerTests
```

Expected:

```text
PASS for single active connection enforcement.
```

- [ ] **Step 5: Commit connection state control**

Run:

```powershell
git add windows-client && git commit -m "feat: add windows client connection controller"
```

Expected:

```text
A commit with single active connection orchestration.
```

### Task 7: Build the main WPF shell, tray, and basic profile workflows

**Files:**
- Create: `windows-client/src/WindowsClient.App/App.xaml`
- Create: `windows-client/src/WindowsClient.App/App.xaml.cs`
- Create: `windows-client/src/WindowsClient.App/MainWindow.xaml`
- Create: `windows-client/src/WindowsClient.App/MainWindow.xaml.cs`
- Create: `windows-client/src/WindowsClient.App/ViewModels/MainWindowViewModel.cs`
- Create: `windows-client/src/WindowsClient.App/Views/ProfileWizardWindow.xaml`
- Create: `windows-client/src/WindowsClient.App/Views/ProfileWizardWindow.xaml.cs`
- Create: `windows-client/src/WindowsClient.App/ViewModels/ProfileWizardViewModel.cs`

- [ ] **Step 1: Add a shell-level smoke test or manual verification checklist**

Because WPF UI automation is often heavier than the first MVP needs, add at least a manual verification checklist file or lightweight app-layer tests covering:

```text
- Main window opens
- Profile list is visible
- Logs / Diagnostics / Profile Details tabs exist
- Closing the window minimizes to tray
- Tray menu contains only the approved six items
```

- [ ] **Step 2: Implement the main window structure**

Build `MainWindow.xaml` with:

- left profile list
- top-right connection control card
- bottom-right tab control with Logs, Diagnostics, and Profile Details

Keep code-behind minimal. Put state and commands into `MainWindowViewModel`.

- [ ] **Step 3: Implement the profile wizard window**

Build a wizard with the approved four steps:

- Basic Connection
- Network Interface
- Security And Advanced Options
- Review And Preflight

Ensure the first step includes the `edge` version selector sourced from version discovery.

- [ ] **Step 4: Implement tray behavior**

Implement tray actions so the right-click menu contains exactly:

```text
- current status
- current active profile name
- connect current selected profile
- disconnect current connection
- open main window
- exit
```

No recent profiles and no recent error entry.

- [ ] **Step 5: Run a build to verify the WPF shell compiles**

Run:

```powershell
dotnet build "windows-client\src\WindowsClient.sln"
```

Expected:

```text
Build succeeds with the WPF shell, view models, and tray integration compiling cleanly.
```

- [ ] **Step 6: Commit the UI shell**

Run:

```powershell
git add windows-client && git commit -m "feat: add windows client shell"
```

Expected:

```text
A commit with the main window, wizard, and tray shell.
```

### Task 8: Add diagnostics, log presentation, and end-to-end MVP integration

**Files:**
- Create: `windows-client/src/WindowsClient.Core/Interfaces/IDiagnosticsService.cs`
- Create: `windows-client/src/WindowsClient.Infrastructure/Diagnostics/DiagnosticsService.cs`
- Modify: `windows-client/src/WindowsClient.App/ViewModels/MainWindowViewModel.cs`
- Modify: `windows-client/src/WindowsClient.App/ViewModels/ProfileWizardViewModel.cs`
- Modify: `windows-client/src/WindowsClient.Infrastructure/Processes/ConnectionController.cs`
- Modify: `windows-client/src/WindowsClient.Infrastructure/Logging/InMemoryLogBuffer.cs`

- [ ] **Step 1: Add failing tests for quick diagnostics of missing version binaries**

Extend or create tests that verify quick diagnostics fail when:

```text
- EdgeVersionId is missing
- bin/<version>/edge.exe is missing
- required profile fields are missing
```

- [ ] **Step 2: Run the diagnostics tests to confirm failure**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.Tests\WindowsClient.Tests.csproj"
```

Expected:

```text
FAIL because diagnostics integration is not complete yet.
```

- [ ] **Step 3: Implement quick and full diagnostics**

Implement a diagnostics service that checks:

- selected version id present
- resolved executable exists
- executable path is launchable
- profile fields complete
- TAP name presence or warning
- supernode host/port validity
- local management port conflict where applicable

Return structured `DiagnosticResult` entries with title, status, reason, and suggestion.

- [ ] **Step 4: Wire logs and diagnostics into the main view model**

Update the main shell so that:

- logs tab shows collected entries from `ILogBuffer`
- diagnostics tab shows the latest quick/full results
- connection failures update the visible status summary
- command preview includes the selected binary version and resolved path

- [ ] **Step 5: Run the full test suite**

Run:

```powershell
dotnet test "windows-client\src\WindowsClient.sln"
```

Expected:

```text
All Windows client tests pass.
```

- [ ] **Step 6: Run the final build**

Run:

```powershell
dotnet build "windows-client\src\WindowsClient.sln"
```

Expected:

```text
The full Windows client solution builds successfully.
```

- [ ] **Step 7: Commit the MVP integration**

Run:

```powershell
git add windows-client && git commit -m "feat: deliver windows client mvp"
```

Expected:

```text
A commit with the integrated Windows client MVP.
```
