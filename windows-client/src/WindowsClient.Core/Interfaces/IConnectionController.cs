using WindowsClient.Core.Models;

namespace WindowsClient.Core.Interfaces;

public interface IConnectionController
{
    ConnectionRuntimeState State { get; }

    Task StartAsync(ProfileModel profile, bool replaceActive, CancellationToken cancellationToken);

    Task StopAsync(CancellationToken cancellationToken);

    Task RestartAsync(ProfileModel profile, CancellationToken cancellationToken);
}
