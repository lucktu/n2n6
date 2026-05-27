using WindowsClient.Core.Models;

namespace WindowsClient.Core.Interfaces;

public interface IProfileStore
{
    Task<ClientConfigModel> LoadAsync(CancellationToken cancellationToken);

    Task SaveAsync(ClientConfigModel config, CancellationToken cancellationToken);
}
