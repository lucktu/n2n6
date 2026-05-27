using WindowsClient.Core.Interfaces;
using WindowsClient.Core.Models;

namespace WindowsClient.Infrastructure.Processes;

public sealed class ConnectionController : IConnectionController
{
    public ConnectionRuntimeState State { get; } = new();

    public async Task StartAsync(ProfileModel profile, bool replaceActive, CancellationToken cancellationToken)
    {
        if (State.ActiveProfileId.HasValue && State.ActiveProfileId != profile.Id && !replaceActive)
        {
            throw new InvalidOperationException("An active connection already exists.");
        }

        State.PendingProfileId = profile.Id;
        State.Status = "validating";

        await Task.Yield();
        cancellationToken.ThrowIfCancellationRequested();

        State.Status = "starting";
        State.ActiveProfileId = profile.Id;
        State.PendingProfileId = null;
        State.SelectedProfileId = profile.Id;
        State.Status = "running";
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        State.Status = "stopping";
        State.ActiveProfileId = null;
        State.PendingProfileId = null;
        State.Status = "idle";
        return Task.CompletedTask;
    }

    public async Task RestartAsync(ProfileModel profile, CancellationToken cancellationToken)
    {
        State.Status = "restarting";
        await StopAsync(cancellationToken);
        await StartAsync(profile, replaceActive: true, cancellationToken);
    }

    public Task MarkRunningForTestAsync(ProfileModel profile)
    {
        State.ActiveProfileId = profile.Id;
        State.SelectedProfileId = profile.Id;
        State.Status = "running";
        return Task.CompletedTask;
    }
}
