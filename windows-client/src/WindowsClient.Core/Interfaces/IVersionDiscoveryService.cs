using WindowsClient.Core.Models;

namespace WindowsClient.Core.Interfaces;

public interface IVersionDiscoveryService
{
    Task<IReadOnlyList<VersionInfoModel>> DiscoverAsync(CancellationToken cancellationToken);
}
